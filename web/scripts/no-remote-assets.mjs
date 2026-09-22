/**
 * Nothing in this application fetches anything from the internet.
 *
 * `docs/UI-3D-DEVICE-EXPLORER.md` §9: *"No remote assets or telemetry; this must run in an
 * air-gapped deployment."* §8's Phase 1 exit list says the same thing as a step: *"Verify
 * no branded or downloaded assets enter the build."*
 *
 * This is the check, and it runs against the **built** bundle rather than the source,
 * because the failure it is looking for is not usually written by hand. A font helper, an
 * icon set, a model loader with a default CDN base, a source map comment pointing at a
 * published package — all of them put a hostname in the output that nobody typed. An
 * air-gapped deployment discovers it as a render that never finishes and a console full of
 * failed requests, which is the worst possible place to find out.
 *
 * # What counts as a hit
 *
 * A URL with a scheme and a host, in a file the browser will load. Not a bare word that
 * happens to contain a dot, not a URL inside a `.map` — source maps are a development
 * artefact and are not served to an air-gapped operator — and not the handful of strings
 * that are documentation rather than a request.
 *
 * # Why an allow-list exists at all
 *
 * The product legitimately *names* external things: an XML namespace on an SVG element, a
 * schema URL in a comment, a documentation link in an error message. Those are text. The
 * distinction this script draws is between a hostname that appears and a hostname that is
 * fetched, and since it cannot execute the bundle to tell, the allow-list is the place
 * where each exception is written down with a reason.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// `fileURLToPath`, not `new URL(...).pathname`: on Windows the latter yields `/C:/...`,
// which is not a path any filesystem call accepts. The CSS guard learned this first.
const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, "..", "dist");

/**
 * Hostnames that may appear as text in the bundle, and why.
 *
 * Each entry is a substring match and each one needs a reason. An empty list would be
 * better and is not achievable: SVG carries its namespace in every element.
 */
const ALLOWED = [
  // The SVG namespace. It is an identifier, not an address — nothing fetches it — and it
  // is required on every `<svg>` element the topology and the charts draw.
  "http://www.w3.org/2000/svg",
  "http://www.w3.org/1999/xhtml",
  "http://www.w3.org/1999/xlink",
  "http://www.w3.org/1998/Math/MathML",
  "http://www.w3.org/XML/1998/namespace",
  // React's own error messages carry a link to the page explaining the error. It is
  // printed to a console, never requested, and an operator reading it has already decided
  // whether their browser can reach the internet.
  "https://react.dev/errors/",
  // A citation. three.js names the paper an algorithm came from in a source comment, which
  // survives minification as a string.
  "https://jcgt.org/published/",
  // The product's own placeholder in the webhook form: what a URL looks like, in a field
  // an operator types their own into. `.internal` is reserved and resolves nowhere.
  "http://hooks.internal/",
];

/** What the browser actually loads. Source maps are not served. */
const SERVED = /\.(js|css|html)$/;

const URLS = /\b(?:https?:)?\/\/[a-z0-9._-]+\.[a-z]{2,}(?:[/:?][^\s"'`)\]]*)?/gi;

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else out.push(path);
  }
  return out;
}

let files;
try {
  files = walk(dist).filter((f) => SERVED.test(f));
} catch {
  console.error("no dist/ to check — run `npm run build` first");
  process.exit(1);
}

if (files.length === 0) {
  console.error("dist/ has no served files — the build produced nothing to check");
  process.exit(1);
}

const hits = [];
for (const file of files) {
  const text = readFileSync(file, "utf8");
  for (const match of text.matchAll(URLS)) {
    const url = match[0];
    if (ALLOWED.some((allowed) => url.startsWith(allowed))) continue;
    hits.push(`${file.slice(dist.length + 1)}: ${url.slice(0, 120)}`);
  }
}

if (hits.length > 0) {
  for (const hit of [...new Set(hits)].sort()) console.error(hit);
  console.error(
    `\nremote reference in the built bundle: ${hits.length} occurrence(s). This product ` +
      "has to run air-gapped — see docs/UI-3D-DEVICE-EXPLORER.md §9. Vendor the asset, or " +
      "add it to ALLOWED in this script with the reason it is text rather than a request.",
  );
  process.exit(1);
}

console.log(`ok: no remote references in ${files.length} served file(s)`);
