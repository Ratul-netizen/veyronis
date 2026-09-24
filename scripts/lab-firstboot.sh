#!/bin/bash
# Name a lab node after its EVE-NG node number, and give it the role that number implies.
#
# `docs/lab.md` said this script was "recorded in docs/dev-environment.md". It was not
# recorded anywhere: it existed only inside `linux-uopsnode`'s qcow2 on the EVE-NG guest,
# which meant the lab could not be rebuilt, inspected or reasoned about without extracting it
# from a disk image. It lives here now, and the image is built by installing this file.
#
# # How a node knows what it is
#
# EVE-NG does not inject configuration into a plain Linux node — no cloud-init datasource, no
# metadata service. The one thing a node can observe about its place in the topology is its
# own MAC: EVE-NG assigns `00:50:00:00:0N:00` to node *N*'s first interface. So the node
# number is read out of the MAC and everything else follows from a table.
#
# The previous version of this table named nodes 02, 03 and 04 and fell through to
# `NAME=edge-fw` for everything else. Adding five nodes to the lab therefore produced five
# devices that told the product, over SNMP, that they were all `edge-fw`. The fallback below
# is `node-NN` instead: still wrong, but wrong in a way that is visibly a gap rather than a
# plausible lie.
#
# # The two networks, and why the second one exists
#
# **Mgmt** is the real LAN, bridged through `pnet0`, and every *fabric* device sits on it by
# DHCP. That is out-of-band management, which is how a datacenter is actually run: an
# operator does not lose the ability to see a switch because the switch stopped forwarding.
#
# **The workload subnets** are `10.10.<leaf>.0/24`, one per leaf, and the servers live only
# there. They reach the world through their leaf, which forwards. This is what makes the
# dependency real: `leaf-01` going down genuinely takes `lb-01` and `app-01` with it, so M9's
# topology-aware suppression is exercised against a graph that means something rather than
# against a fixture. A flat /24 where every node is directly reachable would make the
# suppression test cosmetic.
#
# The monitoring host needs a route to each workload subnet via the leaf that owns it; the
# command is printed at the end of `docs/lab.md` §6 because it has to be run on the host, not
# here.

set -e
MARK=/var/lib/uops-firstboot.done
[ -f "$MARK" ] && exit 0

# sshd will not start without host keys, and the image ships none on purpose — a golden image
# carrying its host keys gives every clone the same identity.
ssh-keygen -A >/dev/null 2>&1 || true

FIRST=$(ip -o link | awk -F': ' '$2 != "lo" {print $2; exit}')
MAC=$(cat "/sys/class/net/$FIRST/address")
SHORT=$(echo "$MAC" | tr -d ':' | tail -c 7)
NODE=$(echo "$MAC" | cut -d: -f5)

# node -> name, role, and (for a workload) the leaf subnet it belongs to.
#
#   core-rtr-01 ── edge-fw ── spine-01 ─┬─ leaf-01 ─┬─ lb-01
#                                       │           └─ app-01
#                                       └─ leaf-02 ─┬─ app-02
#                                                   └─ db-01
case "$NODE" in
  01) NAME=edge-fw     ROLE=fabric ;;
  02) NAME=spine-01    ROLE=fabric ;;
  03) NAME=lb-01       ROLE=workload SUBNET=6 HOST=10 ;;
  04) NAME=app-01      ROLE=workload SUBNET=6 HOST=11 ;;
  05) NAME=core-rtr-01 ROLE=fabric ;;
  06) NAME=leaf-01     ROLE=leaf LEAFNET=6 ;;
  07) NAME=leaf-02     ROLE=leaf LEAFNET=7 ;;
  08) NAME=app-02      ROLE=workload SUBNET=7 HOST=10 ;;
  09) NAME=db-01       ROLE=workload SUBNET=7 HOST=11 ;;
  *)  NAME="node-$NODE" ROLE=fabric ;;
esac

hostnamectl set-hostname "$NAME-$SHORT"
sed -i "s/^127.0.1.1.*/127.0.1.1\t$NAME-$SHORT/" /etc/hosts || true

rm -f /etc/systemd/network/*.network

case "$ROLE" in
fabric)
  # Mgmt by DHCP; the data-plane links carry link-local addressing only, which is enough for
  # LLDP to run on them. LLDP has to be on the links that form the topology, not only on the
  # one the product polls over.
  cat > /etc/systemd/network/10-mgmt.network <<'NET'
[Match]
Name=ens3
[Network]
DHCP=yes
LLDP=yes
EmitLLDP=yes
[DHCPv4]
UseHostname=no
ClientIdentifier=mac
NET
  cat > /etc/systemd/network/20-links.network <<'NET'
[Match]
Name=ens4
Name=ens5
Name=ens6
[Network]
LinkLocalAddressing=ipv4
LLDP=yes
EmitLLDP=yes
NET
  ;;

leaf)
  # A leaf is on Mgmt like the rest of the fabric, and is the gateway for its own workload
  # subnet on the two downstream links.
  cat > /etc/systemd/network/10-mgmt.network <<'NET'
[Match]
Name=ens3
[Network]
DHCP=yes
LLDP=yes
EmitLLDP=yes
[DHCPv4]
UseHostname=no
ClientIdentifier=mac
NET
  # The spine link: link-local, for LLDP.
  cat > /etc/systemd/network/20-uplink.network <<'NET'
[Match]
Name=ens4
[Network]
LinkLocalAddressing=ipv4
LLDP=yes
EmitLLDP=yes
NET
  # Both downstream links are the same /24 — a leaf's servers share its subnet, which is
  # what a top-of-rack switch does. Bridged rather than routed between the two ports so the
  # servers are on one L2 segment.
  cat > /etc/systemd/network/25-workload.netdev <<'NET'
[NetDev]
Name=wl0
Kind=bridge
NET
  cat > /etc/systemd/network/26-workload-ports.network <<'NET'
[Match]
Name=ens5
Name=ens6
[Network]
Bridge=wl0
LLDP=yes
EmitLLDP=yes
NET
  cat > /etc/systemd/network/27-workload-bridge.network <<NET
[Match]
Name=wl0
[Network]
Address=10.10.$LEAFNET.1/24
IPForward=yes
NET
  cat > /etc/sysctl.d/99-uops-leaf.conf <<'SYS'
net.ipv4.ip_forward=1
SYS
  ;;

workload)
  # Only on its leaf's subnet. Nothing on Mgmt: reaching this server means going through
  # the leaf, which is the dependency the estate exists to model.
  cat > /etc/systemd/network/10-workload.network <<NET
[Match]
Name=ens4
[Network]
Address=10.10.$SUBNET.$HOST/24
Gateway=10.10.$SUBNET.1
DNS=192.168.1.1
LLDP=yes
EmitLLDP=yes
NET
  # ens3 is cabled to Mgmt by the topology builder so that every node *can* be reached
  # while the lab is being brought up, and is held down here so that it is not. Two paths to
  # one server would mean the suppression test passes whether or not suppression works.
  cat > /etc/systemd/network/90-mgmt-down.network <<'NET'
[Match]
Name=ens3
[Link]
ActivationPolicy=always-down
NET
  ;;
esac

sysctl --system >/dev/null 2>&1 || true
systemctl restart systemd-networkd
systemctl restart snmpd lldpd rsyslog ssh 2>/dev/null || true
touch "$MARK"
