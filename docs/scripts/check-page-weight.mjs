import NodeFS from 'node:fs'
import NodePath from 'node:path'
import Process from 'node:process'

// Guards the weight a reader actually downloads to view a page.
//
// This is not Lighthouse: it measures bytes, not rendering. It exists because page
// weight is the performance input that regresses silently through ordinary work —
// a component import pulls in a charting library and nothing fails.
//
// The metric is deliberately *initial payload per page*: the HTML document plus
// the scripts and stylesheets that document references. Total bytes on disk is the
// wrong measure here, because the build emits large chunks that are only fetched
// on demand — the API playground is ~2.9 MB and is referenced by no page's initial
// HTML. Budgeting against on-disk totals would fail the build over code no reader
// downloads, and that kind of false alarm is how a guardrail gets disabled.
const BUDGETS = {
  // Initial payload for a single page: HTML + referenced JS/CSS. Set just above
  // the current worst page so growth is caught rather than absorbed.
  //
  // The API reference pages are the heaviest, and deliberately so: their endpoint
  // documentation is prerendered into the HTML, which is what makes it indexable
  // and what puts it in the markdown mirror. That weight is content a reader came
  // for, not framework overhead, so the budget accommodates it.
  maxPageInitialKb: 1200,
  // Largest single asset in an initial payload. Guards against a heavy library
  // re-entering the shared chunk graph.
  maxInitialAssetKb: 400,
  // Largest prerendered HTML document.
  maxHtmlKb: 350,
}

const distRoot = ['dist/public', 'dist']
  .map((d) => NodePath.join(Process.cwd(), d))
  .find((d) => NodeFS.existsSync(NodePath.join(d, 'index.html')))

if (!distRoot) {
  throw new Error('check-page-weight: no built output found — run `vocs build` first')
}

function walk(dir) {
  const out = []
  for (const entry of NodeFS.readdirSync(dir, { withFileTypes: true })) {
    const full = NodePath.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...walk(full))
    else out.push(full)
  }
  return out
}

const sizeOf = (relPath) => {
  try {
    return NodeFS.statSync(NodePath.join(distRoot, relPath)).size
  } catch {
    return 0
  }
}
const kb = (bytes) => Math.round(bytes / 1024)

const htmlFiles = walk(distRoot)
  .filter((f) => f.endsWith('.html'))
  .map((f) => NodePath.relative(distRoot, f))
  .filter((f) => !f.startsWith('404') && !f.startsWith('_root'))

const pages = []
for (const rel of htmlFiles) {
  const html = NodeFS.readFileSync(NodePath.join(distRoot, rel), 'utf8')
  const htmlSize = Buffer.byteLength(html)

  // Assets the document itself references, i.e. what a first visit fetches.
  const referenced = new Set(
    [...html.matchAll(/(?:assets\/[A-Za-z0-9._-]+\.(?:js|css))/g)].map(([m]) => m),
  )
  let assetBytes = 0
  let largest = { path: '', size: 0 }
  for (const asset of referenced) {
    const size = sizeOf(asset)
    assetBytes += size
    if (size > largest.size) largest = { path: asset, size }
  }

  pages.push({
    page: rel.replace(/\/index\.html$/, '') || '/',
    htmlKb: kb(htmlSize),
    initialKb: kb(htmlSize + assetBytes),
    assetCount: referenced.size,
    largest,
  })
}

pages.sort((a, b) => b.initialKb - a.initialKb)

console.log(`check-page-weight: ${pages.length} pages`)
console.log('  heaviest initial payloads:')
for (const p of pages.slice(0, 5)) {
  console.log(`    ${String(p.initialKb).padStart(5)} KB  ${p.page}  (${p.assetCount} assets, html ${p.htmlKb} KB)`)
}

const failures = []
for (const p of pages) {
  if (p.initialKb > BUDGETS.maxPageInitialKb) {
    failures.push(`${p.page}: initial payload ${p.initialKb} KB exceeds ${BUDGETS.maxPageInitialKb} KB`)
  }
  if (p.htmlKb > BUDGETS.maxHtmlKb) {
    failures.push(`${p.page}: HTML ${p.htmlKb} KB exceeds ${BUDGETS.maxHtmlKb} KB`)
  }
  if (kb(p.largest.size) > BUDGETS.maxInitialAssetKb) {
    failures.push(
      `${p.page}: asset ${p.largest.path} is ${kb(p.largest.size)} KB, over the ${BUDGETS.maxInitialAssetKb} KB per-asset budget`,
    )
  }
}

if (failures.length > 0) {
  console.error('\ncheck-page-weight: budget exceeded')
  for (const f of failures) console.error(`  ${f}`)
  console.error('\nEither reduce the weight, or raise the budget in this file as part of the same change.')
  Process.exit(1)
}

console.log('check-page-weight: all pages within budget')
