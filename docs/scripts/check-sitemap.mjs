import NodeFS from 'node:fs'
import NodePath from 'node:path'
import Process from 'node:process'
import { SITE_URL, collectRoutes, findDistRoot, isIndexableRoute } from './dist.mjs'

// Verifies the sitemap against what the build actually produced.
//
// A sitemap is a set of promises to crawlers. Listing a URL that does not exist
// spends crawl budget on 404s and erodes trust in the whole file; omitting a page
// that does exist leaves it to be discovered by luck. Both drift silently as pages
// are added or renamed, which is why this is a build step rather than a review
// item.
const distRoot = findDistRoot('check-sitemap')

const sitemapPath = NodePath.join(distRoot, 'sitemap.xml')
if (!NodeFS.existsSync(sitemapPath)) {
  throw new Error(`check-sitemap: ${sitemapPath} is missing`)
}

const sitemap = NodeFS.readFileSync(sitemapPath, 'utf8')
const listed = new Set(
  [...sitemap.matchAll(/<loc>(.*?)<\/loc>/g)].map(([, loc]) => {
    const path = loc.replace(SITE_URL, '')
    return path === '' ? '/' : path.replace(/\/$/, '') || '/'
  }),
)

const built = new Set(collectRoutes(distRoot).filter(isIndexableRoute))

const phantom = [...listed].filter((r) => !built.has(r)).sort()
const unlisted = [...built].filter((r) => !listed.has(r)).sort()

console.log(`check-sitemap: ${listed.size} listed, ${built.size} built`)

if (phantom.length > 0) {
  console.error(`\ncheck-sitemap: ${phantom.length} sitemap URL(s) have no built page:`)
  for (const r of phantom) console.error(`  ${r}`)
}
if (unlisted.length > 0) {
  console.error(`\ncheck-sitemap: ${unlisted.length} built page(s) missing from the sitemap:`)
  for (const r of unlisted) console.error(`  ${r}`)
}
if (phantom.length > 0 || unlisted.length > 0) Process.exit(1)

console.log('check-sitemap: sitemap and built output agree')
