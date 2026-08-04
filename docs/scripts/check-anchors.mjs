import NodeFS from 'node:fs'
import NodePath from 'node:path'
import Process from 'node:process'
import { collectHtmlFiles, findDistRoot, isIndexableRoute } from './dist.mjs'

// Fails the build when a link points at a `#fragment` that no longer exists.
//
// Vocs' `checkDeadlinks` resolves only the page half of an internal link, so
// `/security/overview#gone` passes as long as the page exists. The fragment is the
// half that rots: headings get reworded far more often than pages get moved, and
// the reader lands at the top of a long page with nothing indicating the target
// went missing.
//
// This reads the built HTML rather than the MDX sources. Two thirds of this site's
// routes are generated from the OpenAPI specs and have no source file to walk, so a
// source-level check would be blind to exactly the pages whose headings are derived
// from a vendored document. Reading the output also means the anchors compared are
// the ones a browser will actually resolve, not a reimplementation of the slugger.
const distRoot = findDistRoot('check-anchors')

/** `security/overview/index.html` -> `/security/overview`, `index.html` -> `/`. */
function routeForHtmlFile(rel) {
  const route = `/${rel}`.replace(/\/index\.html$/, '').replace(/\.html$/, '')
  return route === '' ? '/' : route
}

const pages = collectHtmlFiles(distRoot)
  .map((rel) => ({ rel, route: routeForHtmlFile(rel) }))
  .filter((page) => isIndexableRoute(page.route))

const anchorsByRoute = new Map()
const linksByRoute = new Map()

for (const page of pages) {
  const html = NodeFS.readFileSync(NodePath.join(distRoot, page.rel), 'utf8')
  anchorsByRoute.set(page.route, new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => id)))
  linksByRoute.set(page.route, [...new Set([...html.matchAll(/\bhref="([^"]*#[^"]*)"/g)].map(([, href]) => href))])
}

const failures = []
let linksChecked = 0

for (const page of pages) {
  for (const href of linksByRoute.get(page.route) ?? []) {
    // Only same-origin links resolve against a page in this build; anything
    // carrying a scheme belongs to the external link checker.
    if (!href.startsWith('/') && !href.startsWith('#')) continue

    // Any absolute origin works: the URL is parsed for its path and fragment only.
    const url = new URL(href, `https://docs.invalid${page.route}`)
    const fragment = decodeURIComponent(url.hash.slice(1))
    if (!fragment) continue

    const target = url.pathname.replace(/\/$/, '') || '/'
    // An unknown route is a dead link rather than a dead anchor, and `checkDeadlinks`
    // already owns that. Reporting it here too would duplicate the failure.
    const anchors = anchorsByRoute.get(target)
    if (!anchors) continue

    linksChecked += 1
    if (anchors.has(fragment)) continue
    failures.push({ page: page.route, href, target, fragment })
  }
}

console.log(`check-anchors: ${linksChecked} anchored link(s) across ${pages.length} page(s)`)

if (failures.length > 0) {
  console.error(`\ncheck-anchors: ${failures.length} link(s) point at a missing anchor:`)
  for (const f of failures) {
    console.error(`  ${f.page}  ${f.href}  — ${f.target} has no #${f.fragment}`)
  }
  console.error('\nEither fix the link or restore the heading it points at.')
  Process.exit(1)
}

console.log('check-anchors: every anchored link resolves')
