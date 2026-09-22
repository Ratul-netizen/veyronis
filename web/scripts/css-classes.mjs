/**
 * Every CSS class the markup names must exist in the stylesheet.
 *
 * This exists because the same mistake has been made three times: `.num` in M7,
 * `.actions` in M9, and four classes found only when this check was written — `.error`,
 * `.muted`, `.notice` and `.palette-label`, each of which had been rendering as unstyled
 * text in a shipped screen.
 *
 * Nothing fails when it happens. There is no console warning, no build error, and no
 * visual difference large enough to notice in a diff: the element simply inherits the
 * page and looks slightly wrong to somebody who is not looking for it. That is exactly
 * the class of defect a guard is for and a review is not.
 *
 * # Only literal classes
 *
 * `className="a b"` is checked; `className={...}` is not, and cannot usefully be without
 * evaluating the expression. That is not a gap worth closing: every one of the seven
 * misses above was a literal, which is the shape the mistake actually takes.
 *
 *     node scripts/css-classes.mjs
 */

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

// `fileURLToPath` rather than `.pathname`, which on Windows yields `/C:/...` and turns
// every later `join` into a path with a drive letter in the middle of it.
const SRC = fileURLToPath(new URL("../src/", import.meta.url));

const css = readFileSync(join(SRC, "styles.css"), "utf8");
// Every class selector in the stylesheet, including the ones inside a compound like
// `.palette-results li.on` — which is a definition of `.on` as much as of anything else.
const defined = new Set([...css.matchAll(/\.([a-zA-Z][\w-]*)/g)].map((m) => m[1]));

const missing = [];
for (const file of readdirSync(SRC).filter((f) => f.endsWith(".tsx"))) {
  const source = readFileSync(join(SRC, file), "utf8");
  for (const match of source.matchAll(/className="([^"{}]+)"/g)) {
    for (const name of match[1].trim().split(/\s+/)) {
      if (name && !defined.has(name)) missing.push(`src/${file}: .${name}`);
    }
  }
}

if (missing.length > 0) {
  console.error([...new Set(missing)].sort().join("\n"));
  console.error(
    `::error::${missing.length} class(es) are named in the markup and defined in no stylesheet`,
  );
  process.exit(1);
}

console.log(`ok: every class in the markup is defined (${defined.size} in the stylesheet)`);
