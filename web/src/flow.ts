/**
 * The queries the flow screen asks, and the one arithmetic decision it makes.
 *
 * # The sampling rate is not a detail, and this is where the UI has to prove it
 *
 * `docs/M7-flow.md` §2.4: a flow's `bytes` is what the exporter *observed*, and
 * `sampling_rate` says what it stands for. One packet in a thousand means the byte count
 * is roughly a thousandth of the traffic. The product stores the observed number and
 * multiplies at read time, deliberately, so that the measurement is never lost.
 *
 * Which leaves this file with the decision. Showing the observed number labelled "bytes"
 * would under-report a sampled exporter by three orders of magnitude. Showing the
 * multiplied number labelled "bytes" would present an estimate as a measurement, which
 * UI-SPEC forbids — the product may visualise backend truth and may not invent it.
 *
 * So the screen shows the estimate, because that is the number an operator is asking
 * about, and [`Traffic.estimated`] says when it is one. Every row that carries it is
 * marked, and a row from an unsampled exporter is not marked, because it is not an
 * estimate.
 */

import { runQuery, type Field, type Query, type ResultSet } from "./query";

/** How many conversations the screen lists. */
export const TOP_N = 25;

/**
 * Top conversations in a window.
 *
 * Grouped by the sampling rate as well as the conversation, which is the planner's rule
 * (`serves_from_flows_5m`) and the reason it can use `flows_5m` at all: summing bytes
 * across rows sampled differently produces a number that is neither an estimate nor a
 * measurement. Dropping `sampling_rate` here would silently move this query onto the raw
 * table and make its answer meaningless at the same time.
 */
/**
 * The busiest conversations in a window.
 *
 * `resource` narrows it to one device's flows — M11 §2.6 shows a firewall's denials beside
 * its traffic, and the alternative was a second flow query living in the security module.
 * A second copy of flow analytics with the word "security" on it is exactly what §2.6 says
 * not to build, so the scoping goes here instead.
 */
export function topTalkers(
  start: string,
  end: string,
  limit = TOP_N,
  resource?: string,
): Query {
  const rate: Field = { field: "sampling_rate" };
  return {
    signal: "flow",
    time: { start, end },
    resources: resource ? { type: "ids", ids: [resource] } : { type: "all" },
    aggregations: [
      { func: "sum", field: { field: "bytes" }, alias: "bytes" },
      { func: "sum", field: { field: "packets" }, alias: "packets" },
    ],
    group_by: [
      { field: "src_address" },
      { field: "dst_address" },
      { field: "dst_port" },
      { field: "protocol" },
      rate,
    ],
    order_by: [{ key: { by: "alias", alias: "bytes" }, desc: true }],
    limit,
  };
}

/** One conversation, as the screen shows it. */
export interface Conversation {
  src: string;
  dst: string;
  port: number;
  protocol: number;
  samplingRate: number;
  /** Bytes and packets as the exporter observed them. */
  observedBytes: number;
  observedPackets: number;
}

/** What a number means, once the sampling rate has been applied. */
export interface Traffic {
  value: number;
  /** True when the exporter was sampling, so this is extrapolated rather than counted. */
  estimated: boolean;
}

export function traffic(observed: number, samplingRate: number): Traffic {
  return {
    value: observed * samplingRate,
    // A rate of 1 is "every packet was seen", so the number is a measurement. The
    // decoders clamp the rate up to 1 and never to 0, which is what makes this safe to
    // multiply by without checking.
    estimated: samplingRate > 1,
  };
}

/** Column index by name, because the server sends rows as arrays and not objects. */
function indexer(result: ResultSet): (name: string) => number {
  const at = new Map(result.columns.map((c, i) => [c.name, i]));
  return (name) => at.get(name) ?? -1;
}

/**
 * Turn a result set into conversations.
 *
 * The grouped columns come back as `g0`, `g1`, … in the order they were grouped — the
 * compiler names them that way — so this reads them positionally and the order here has
 * to match [`topTalkers`]. A mismatch would silently swap two columns, which is why the
 * two functions are adjacent and why the test asserts a round trip rather than a shape.
 */
export function conversations(result: ResultSet): Conversation[] {
  const index = indexer(result);
  const at = {
    src: index("g0"),
    dst: index("g1"),
    port: index("g2"),
    protocol: index("g3"),
    rate: index("g4"),
    bytes: index("bytes"),
    packets: index("packets"),
  };
  // A column the query asked for and the server did not send means the two have drifted.
  // Returning nothing is the honest answer: a partial row here would be a conversation
  // with somebody else's address in it.
  if (Object.values(at).some((i) => i < 0)) return [];

  return result.rows.map((row) => ({
    src: String(row[at.src] ?? ""),
    dst: String(row[at.dst] ?? ""),
    port: number(row[at.port]),
    protocol: number(row[at.protocol]),
    samplingRate: Math.max(1, number(row[at.rate])),
    observedBytes: number(row[at.bytes]),
    observedPackets: number(row[at.packets]),
  }));
}

/**
 * A number, however `ClickHouse` chose to encode it.
 *
 * 64-bit integers arrive quoted when `output_format_json_quote_64bit_integers` is on,
 * and byte counts are exactly the column where that matters.
 */
function number(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

/**
 * An address as the table shows it.
 *
 * Every address is stored as IPv6 with IPv4 mapped — one column, both families — so a v4
 * address comes back as `::ffff:10.0.0.7`. Showing that to an operator looking for
 * 10.0.0.7 is showing them something they have to decode, so the mapping is undone here.
 */
export function displayAddress(address: string): string {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  return mapped?.[1] ?? address;
}

/** IANA protocol numbers worth a name. Anything else is shown as its number. */
const PROTOCOLS = new Map([
  [1, "ICMP"],
  [6, "TCP"],
  [17, "UDP"],
  [47, "GRE"],
  [50, "ESP"],
  [58, "ICMPv6"],
  [89, "OSPF"],
  [132, "SCTP"],
]);

export function protocolName(protocol: number): string {
  return PROTOCOLS.get(protocol) ?? String(protocol);
}

/**
 * Whether a port number means anything for this protocol.
 *
 * ICMP has no ports, and the column holds 0 for it — which is not "port zero", it is
 * "there is no port". Printing the 0 would be the same mistake the decoders refuse to
 * make with an AS number: a legitimate value standing in for an absent one, with nothing
 * to tell them apart.
 */
export function hasPorts(protocol: number): boolean {
  // TCP, UDP, SCTP, DCCP, UDP-Lite.
  return [6, 17, 132, 33, 136].includes(protocol);
}

/**
 * Bytes, as a person reads them.
 *
 * Decimal units, because network equipment counts in decimal: a vendor's "1 Gbps" is
 * 10^9 and an operator comparing this against an interface counter should not have to
 * remember which of the two is which.
 */
export function humanBytes(value: number): string {
  const units = ["B", "kB", "MB", "GB", "TB", "PB"];
  let n = value;
  let unit = 0;
  while (n >= 1000 && unit < units.length - 1) {
    n /= 1000;
    unit += 1;
  }
  const digits = n < 10 && unit > 0 ? 1 : 0;
  return `${n.toFixed(digits)} ${units[unit]}`;
}

/** The count, grouped with thousands separators. */
export function humanCount(value: number): string {
  return value.toLocaleString("en-GB");
}

export { runQuery };
