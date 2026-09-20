//! The order things happen in, and who waits for whom.
//!
//! ```text
//!   UdpSocket ─► decode ─► mpsc<Seen> ─┬─► worker ─┐
//!   (one per tenant, owns its          ├─► worker ─┼─► mpsc<FlowRow> ─► batch ─► ClickHouse
//!    template cache)                   └─► worker ─┘
//!                                          (resolve)        (one, shared)
//! ```
//!
//! # Why decoding happens in the receive loop and resolution does not
//!
//! The template cache is mutable state — `uops_flow::templates::Learned` — and a v9 data
//! record cannot be read without it. Decoding inside the receive loop means that loop
//! owns the cache outright: no mutex, no contention, and every packet from one exporter is
//! decoded by the task that learned its templates.
//!
//! Resolution is the opposite. It awaits `PostgreSQL` on a cache miss, and one worker
//! would stall every flow behind one slow lookup — so it fans out, exactly as the syslog
//! collector's does and for the same reason.
//!
//! Decoding is cheap enough to belong on the hot path: it is bounds checks and integer
//! reads, with no allocation beyond the flows themselves.
//!
//! # Where backpressure comes from, and where it stops
//!
//! A slow `ClickHouse` slows the batcher, which fills the row channel, which slows the
//! workers, which fills the `Seen` channel — and there the chain ends, because the
//! receive loop uses `try_send` and drops.
//!
//! It has to. UDP has no back channel, so a receiver that blocks does not slow the
//! exporter down; it just lets the kernel's buffer overflow instead, and a drop in the
//! kernel is invisible where a drop here is a number an operator can see.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use tokio::sync::mpsc;
use uops_core::{IdentifierKind, ObservedIdentity, ResourceId, TenantId};
use uops_flow::templates::Learned;
use uops_flow::{Flow, ipfix, sflow, v5, v9};
use uops_identity::{IdentityStore, Resolver};
use uops_pipeline::{Enrichment, Pipeline, batch};
use uops_store_ch::{ChStore, FlowRow};
use uops_store_pg::{PgEnricher, PgStore};

use crate::config::{Config, Listener};

/// The largest datagram a flow exporter sends.
///
/// 64 KB is the IPv4 payload ceiling. Real datagrams are one MTU, but an exporter on a
/// jumbo-frame path sends more, and a buffer sized for the common case truncates the
/// uncommon one — which would look like a malformed packet rather than a short read.
const MAX_DATAGRAM: usize = 64 * 1024;

/// What the daemon has done, readable from outside it.
///
/// Every counter here answers a question an operator actually asks, and the ones about
/// loss are separated by *cause* because they have completely different remedies: a
/// queue drop means this process is too slow, and an undecodable packet means an
/// exporter is sending something unexpected.
#[derive(Debug, Default)]
pub struct Stats {
    pub datagrams: AtomicU64,
    pub flows: AtomicU64,
    /// Datagrams no decoder would take — an unknown version, or a malformed packet.
    pub undecodable: AtomicU64,
    /// Data records dropped because their template has not arrived. M7 §2.2, and
    /// non-zero for the first half-minute after any exporter or this daemon restarts.
    pub awaiting_template: AtomicU64,
    /// Flows whose sampling rate could not be established, and so was assumed to be 1.
    ///
    /// Not necessarily a fault — an exporter that is not sampling says nothing about
    /// sampling. It is the only thing that distinguishes "the rate is one" from "we do
    /// not know the rate", which §2.4 turns on.
    pub sampling_unknown: AtomicU64,
    /// Flows dropped because the queue to the workers was full.
    pub dropped_queue: AtomicU64,
}

impl Stats {
    fn bump(counter: &AtomicU64, by: usize) {
        counter.fetch_add(by as u64, Ordering::Relaxed);
    }
}

/// One decoded flow, and where it came from.
struct Seen {
    tenant: TenantId,
    exporter: IpAddr,
    flow: Flow,
}

/// A listener with its tenant resolved.
#[derive(Clone, Debug)]
pub struct Bound {
    pub listener: Listener,
    pub tenant_id: TenantId,
}

/// Turn the configured slugs into tenant ids, failing on the first one that is not there.
///
/// Names the slug. A mistyped tenant is the likeliest mistake in the file and the one
/// whose consequence is quietest — flow filed under the wrong customer, or under none.
///
/// # Errors
///
/// When a slug names no tenant, or `PostgreSQL` cannot be asked.
pub async fn resolve_tenants(store: &PgStore, config: &Config) -> Result<Vec<Bound>, String> {
    let mut bound = Vec::new();
    for listener in &config.listeners {
        let tenant_id = store
            .tenant_by_slug(&listener.tenant)
            .await
            .map_err(|e| format!("cannot look up tenant {:?}: {e}", listener.tenant))?
            .ok_or_else(|| {
                format!(
                    "the listener file names tenant {:?}, which does not exist",
                    listener.tenant
                )
            })?;
        bound.push(Bound {
            listener: listener.clone(),
            tenant_id,
        });
    }
    Ok(bound)
}

/// Decide which decoder a datagram belongs to, and run it.
///
/// # The dispatch is subtler than it looks
///
/// `NetFlow` and IPFIX open with a 16-bit version — 5, 9 or 10. sFlow opens with a
/// *32-bit* one, also 5. So a v5 datagram begins `00 05` and an sFlow datagram begins
/// `00 00 00 05`, and reading the first two bytes of the latter gives zero rather than a
/// version. Checking for that zero first is what tells them apart; a collector that reads
/// two bytes and switches would send every sFlow datagram to the v5 decoder, which would
/// reject it as version 0 and count it as malformed.
fn decode(packet: &[u8], exporter: IpAddr, learned: &mut Learned, stats: &Stats) -> Vec<Flow> {
    // One place that counts a refusal, rather than an arm per protocol repeating it.
    let Some(flows) = try_decode(packet, exporter, learned, stats) else {
        stats.undecodable.fetch_add(1, Ordering::Relaxed);
        return Vec::new();
    };
    flows
}

/// The decoders themselves. `None` is "no decoder would take this".
fn try_decode(
    packet: &[u8],
    exporter: IpAddr,
    learned: &mut Learned,
    stats: &Stats,
) -> Option<Vec<Flow>> {
    if packet.len() < 4 {
        return None;
    }

    // sFlow: the high half of its 32-bit version is zero, which no NetFlow version is.
    if packet[0] == 0 && packet[1] == 0 {
        let (_, out) = sflow::decode(packet, Utc::now()).ok()?;
        // A sample this decoder cannot read is not a datagram this decoder cannot read:
        // the rest of the datagram still produced flows.
        Stats::bump(&stats.undecodable, out.unreadable + out.truncated);
        return Some(out.flows);
    }

    match u16::from_be_bytes([packet[0], packet[1]]) {
        5 => {
            let (_, flows) = v5::decode(packet).ok()?;
            Some(flows)
        }
        9 => {
            let (_, out) = v9::decode(packet, exporter, learned).ok()?;
            Stats::bump(&stats.awaiting_template, out.awaiting_template);
            Stats::bump(&stats.sampling_unknown, out.sampling_unknown);
            Some(out.flows)
        }
        10 => {
            let (_, out) = ipfix::decode(packet, exporter, learned).ok()?;
            Stats::bump(&stats.awaiting_template, out.awaiting_template);
            Stats::bump(&stats.sampling_unknown, out.sampling_unknown);
            Some(out.flows)
        }
        _ => None,
    }
}

/// Bind a socket with a receive buffer the kernel was actually asked for.
///
/// `tokio::net::UdpSocket` does not expose `SO_RCVBUF`, and the default is a few hundred
/// kilobytes — perhaps twenty datagrams. Flow arrives in bursts far larger than that, and
/// what overflows is dropped by the kernel before any counter in this process sees it.
fn bind(listener: &Listener, receive_buffer: usize) -> Result<tokio::net::UdpSocket, String> {
    let domain = if listener.udp.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .map_err(|e| format!("cannot create a socket for {}: {e}", listener.udp))?;

    // Best effort: a kernel that will not grant the size still gives a working socket,
    // and refusing to start over a buffer hint would be worse than a smaller buffer.
    let _ = socket.set_recv_buffer_size(receive_buffer);
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("cannot set {} non-blocking: {e}", listener.udp))?;
    socket
        .bind(&listener.udp.into())
        .map_err(|e| format!("cannot bind {}: {e}", listener.udp))?;

    tokio::net::UdpSocket::from_std(socket.into())
        .map_err(|e| format!("cannot register {} with the runtime: {e}", listener.udp))
}

/// Receive, decode, and hand the flows on. One of these per listener.
async fn receive(
    bound: Bound,
    socket: tokio::net::UdpSocket,
    seen: mpsc::Sender<Seen>,
    stats: Arc<Stats>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    // Owned by this task, so the cache needs no lock — see the module documentation.
    let mut learned = Learned::default();
    let mut buffer = vec![0u8; MAX_DATAGRAM];

    loop {
        let (len, from) = tokio::select! {
            result = socket.recv_from(&mut buffer) => match result {
                Ok(pair) => pair,
                // A datagram that could not be read is one datagram. Ending the loop
                // would take the listener down for the rest of the process's life.
                Err(_) => continue,
            },
            _ = shutdown.changed() => break,
        };

        stats.datagrams.fetch_add(1, Ordering::Relaxed);
        let flows = decode(&buffer[..len], from.ip(), &mut learned, &stats);
        Stats::bump(&stats.flows, flows.len());

        for flow in flows {
            let item = Seen {
                tenant: bound.tenant_id,
                exporter: from.ip(),
                flow,
            };
            // try_send, and the drop is the point: see the module documentation on where
            // backpressure stops.
            if seen.try_send(item).is_err() {
                stats.dropped_queue.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Resolve one flow and turn it into a row.
///
/// One flow rather than a receiver: a worker's loop owns the receiving, and a function
/// that owned it too would force the caller to invent a channel per item — which is
/// exactly what the first draft of this file did.
async fn work(
    item: Seen,
    pipeline: &Pipeline<PgStore, PgEnricher>,
    store: &PgStore,
    rows: &mpsc::Sender<FlowRow>,
) -> Result<(), ()> {
    {
        // The exporter, through the same pipeline every other collector uses: matched, or
        // given a provisional resource and a review item. §2.6, as corrected.
        let observed = ObservedIdentity::new("flow")
            .with(IdentifierKind::FlowExporter, item.exporter.to_string());
        let attribution = pipeline.attribute(item.tenant, &observed).await;

        // The endpoints, by lookup only. §2.3: a flow saying 10.0.0.7 talked to 8.8.8.8
        // is not evidence that either exists in inventory, and a product that invents
        // assets from traffic produces a list nobody can trust. Most flows have a nil on
        // at least one end, and every flow to the internet does.
        let src_resource_id = endpoint(store, item.tenant, item.flow.src_address).await;
        let dst_resource_id = endpoint(store, item.tenant, item.flow.dst_address).await;

        let row = FlowRow {
            tenant_id: attribution.tenant_id,
            resource_id: attribution.resource_id,
            site_id: attribution.site_id,
            observed_at: item.flow.observed_at,
            started_at: item.flow.started_at,
            ingested_at: Utc::now(),
            src_address: item.flow.src_address,
            dst_address: item.flow.dst_address,
            src_port: item.flow.src_port,
            dst_port: item.flow.dst_port,
            protocol: item.flow.protocol,
            bytes: item.flow.bytes,
            packets: item.flow.packets,
            sampling_rate: item.flow.sampling_rate,
            tcp_flags: u16::from(item.flow.tcp_flags),
            tos: item.flow.tos,
            input_if: item.flow.input_if,
            output_if: item.flow.output_if,
            src_as: item.flow.src_as,
            dst_as: item.flow.dst_as,
            src_resource_id,
            dst_resource_id,
            attributes: std::collections::BTreeMap::new(),
        };

        // `send` and not `try_send`: this is where backpressure is wanted, because from
        // here down the chain can actually slow the producer.
        rows.send(row).await.map_err(|_| ())
    }
}

/// Which resource an address belongs to, or the nil id.
///
/// `lookup` and never `resolve`: the difference is that one of them creates. §2.3 forbids
/// creating a resource from a flow endpoint, and the trait boundary is what enforces it
/// rather than a comment asking nicely.
async fn endpoint(store: &PgStore, tenant: TenantId, address: IpAddr) -> ResourceId {
    let identifier = uops_core::Identifier::new(IdentifierKind::MgmtIp, address.to_string());
    store
        .lookup(tenant, std::slice::from_ref(&identifier))
        .await
        .ok()
        .and_then(|hits| hits.first().map(|hit| hit.resource_id))
        .unwrap_or_else(ResourceId::nil)
}

/// Bind every listener and run until told to stop.
///
/// # Errors
///
/// When a tenant slug names nothing, or a socket cannot be bound. Both are startup
/// failures on purpose: a collector that came up with three of its four listeners would
/// be silently losing one customer's flow.
pub async fn run(
    config: Config,
    store: PgStore,
    telemetry: ChStore,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<Arc<Stats>, String> {
    let bounds = resolve_tenants(&store, &config).await?;

    // Bound before anything is spawned, so an address already in use is a startup error
    // rather than a task that dies quietly a moment later.
    let mut sockets = Vec::new();
    for bound in &bounds {
        sockets.push((bound.clone(), bind(&bound.listener, config.receive_buffer)?));
    }

    let pipeline = Arc::new(Pipeline::new(
        Resolver::new(store.clone()),
        Enrichment::new(PgEnricher::new(store.clone())),
    ));
    let stats = Arc::new(Stats::default());

    let (rows_tx, rows_rx) = mpsc::channel::<FlowRow>(config.queue);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    let mut receivers = Vec::new();
    let mut workers = Vec::new();

    for (bound, socket) in sockets {
        let (seen_tx, seen_rx) = mpsc::channel::<Seen>(config.queue);
        let seen_rx = Arc::new(tokio::sync::Mutex::new(seen_rx));

        println!(
            "uops-collector-flow: {} listening on {}",
            bound.listener.tenant, bound.listener.udp
        );

        receivers.push(tokio::spawn(receive(
            bound,
            socket,
            seen_tx,
            Arc::clone(&stats),
            stop_rx.clone(),
        )));

        for _ in 0..config.workers.max(1) {
            let (pipeline, store, rows) = (Arc::clone(&pipeline), store.clone(), rows_tx.clone());
            let seen_rx = Arc::clone(&seen_rx);
            workers.push(tokio::spawn(async move {
                // One receiver shared by the listener's workers, which is the ordinary
                // way to fan an mpsc out. The lock is held for the `recv` alone and not
                // across the resolution that follows — holding it there would serialise
                // the workers and undo the reason they exist.
                loop {
                    let item = {
                        let mut guard = seen_rx.lock().await;
                        guard.recv().await
                    };
                    let Some(item) = item else { return };
                    if work(item, &pipeline, &store, &rows).await.is_err() {
                        return;
                    }
                }
            }));
        }
    }
    drop(rows_tx);

    let batcher = tokio::spawn(batch::run(
        telemetry,
        rows_rx,
        batch::Config::default(),
        |s| {
            // rows_dropped is the one that means loss; retries and spills are the
            // system recovering. Reported together so the difference is visible rather
            // than inferred from a single number going up.
            if s.rows_dropped > 0 || s.retries > 0 {
                println!(
                    "uops-collector-flow: {} rows written, {} dropped, {} retries",
                    s.rows_written, s.rows_dropped, s.retries
                );
            }
        },
    ));

    shutdown.await;
    println!("uops-collector-flow: stopping");

    // Receivers first, then the channels close as each stage drains, and the batcher
    // writes what it is holding. A shutdown that dropped the buffer would lose up to a
    // full batch on every deploy.
    let _ = stop_tx.send(true);
    for receiver in receivers {
        let _ = receiver.await;
    }
    for worker in workers {
        let _ = worker.await;
    }
    let _ = batcher.await;

    Ok(stats)
}
