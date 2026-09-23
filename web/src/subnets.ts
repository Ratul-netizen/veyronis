/**
 * Address space — `docs/ipam.md`.
 *
 * The server sends four numbers per range and this file does almost no arithmetic on them,
 * which is deliberate. §2.6: the product reports capacity, assigned and responding, and
 * does not report "97% full" — a single percentage hides whether the remaining space is
 * reserved, and an inventory whose headline number cannot be acted on is a decoration.
 *
 * The one derived number here is `free`, and it is labelled *unknown* rather than
 * *available*: the product sees what answered, and a device that is switched off answers
 * nothing and still owns its address.
 */

import { request } from "./api";

/** How addresses in a range are handed out. A declaration, not an integration. */
export type Assignment = "static" | "dhcp" | "reserved";

export const ASSIGNMENTS: { value: Assignment; label: string; hint: string }[] = [
  {
    value: "static",
    label: "Static",
    hint: "Addresses are assigned by hand or by convention.",
  },
  {
    value: "dhcp",
    label: "DHCP",
    hint: "Handed out by a DHCP server this product does not talk to — utilisation here is what answered, not what is leased.",
  },
  {
    value: "reserved",
    label: "Reserved",
    hint: "Set aside. Anything responding in here is worth a look.",
  },
];

/** One declared range with what is in it. */
export interface Subnet {
  id: string;
  /** CIDR, normalised by `PostgreSQL`. */
  range: string;
  name: string;
  description: string;
  site_id?: string;
  assignment: Assignment;
  /** Usable addresses — /31 and /32 handled by the schema. */
  capacity: number;
  /** Addresses a resource claims as its management address. */
  assigned: number;
  /** Addresses something answered on. Overlaps `assigned` and is not a sum. */
  responding: number;
  /** Answered, and nothing in the inventory claims it. */
  unaccounted: number;
}

/** One address inside a range. */
export interface SubnetAddress {
  address: string;
  resource_id?: string;
  resource_name?: string;
  responding: boolean;
  last_seen?: string;
  unaccounted: boolean;
}

export function listSubnets(tenant: string): Promise<Subnet[]> {
  return request<Subnet[]>("/api/v1/subnets", { tenant });
}

export function declareSubnet(
  tenant: string,
  body: { range: string; name: string; description?: string; assignment?: Assignment },
): Promise<Subnet> {
  return request<Subnet>("/api/v1/subnets", { method: "POST", body, tenant });
}

export function forgetSubnet(tenant: string, id: string): Promise<void> {
  return request<void>(`/api/v1/subnets/${id}`, { method: "DELETE", tenant });
}

export function subnetAddresses(tenant: string, id: string): Promise<SubnetAddress[]> {
  return request<SubnetAddress[]>(`/api/v1/subnets/${id}/addresses`, { tenant });
}

/**
 * Addresses in the range that nothing is known about.
 *
 * **Not "available".** The product sees what answered and what the inventory claims; an
 * address that is switched off is in this number and is not free. The screen says
 * "unknown" for that reason, and `docs/ipam.md` §2.6 refuses to say otherwise.
 *
 * Clamped at zero: `assigned` counts identifiers and `capacity` counts usable addresses,
 * and a range with a management address recorded on its broadcast address — which happens,
 * because somebody typed it — would otherwise render a negative number.
 */
export function unknownAddresses(subnet: Subnet): number {
  const known = Math.max(subnet.assigned, subnet.responding);
  return Math.max(subnet.capacity - known, 0);
}

/**
 * How full a range is, as a fraction, or `null` when that cannot be said.
 *
 * Used for a bar's width only — never shown as a number, per §2.6. `null` for a capacity
 * of zero, which the schema makes impossible today but which a future prefix rule could
 * reintroduce; a bar is better absent than infinitely wide.
 */
export function occupancy(subnet: Subnet): number | null {
  if (subnet.capacity <= 0) return null;
  const known = Math.max(subnet.assigned, subnet.responding);
  return Math.min(known / subnet.capacity, 1);
}

/**
 * Whether a range is worth an operator's attention.
 *
 * One rule, and it is the only judgement this screen makes: something answered in this
 * range that the inventory does not know about. Everything else on the screen is a number
 * the reader interprets.
 */
export function needsAttention(subnet: Subnet): boolean {
  return subnet.unaccounted > 0;
}

/**
 * Ranges ordered as address space is read.
 *
 * The server already returns them in address order. This re-sorts after a local insert so
 * a newly declared range appears where it belongs rather than at the end — and it sorts on
 * the numeric address, because "10.0.10.0/24" sorts before "10.0.9.0/24" as text.
 */
export function inAddressOrder(subnets: Subnet[]): Subnet[] {
  return [...subnets].sort((a, b) => numericRange(a.range) - numericRange(b.range));
}

function numericRange(cidr: string): number {
  const [address = ""] = cidr.split("/");
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isFinite(o))) return 0;
  // Shifts would overflow into a negative for anything above 127.x, so this multiplies.
  return ((octets[0] ?? 0) * 256 + (octets[1] ?? 0)) * 65_536 + (octets[2] ?? 0) * 256 + (octets[3] ?? 0);
}
