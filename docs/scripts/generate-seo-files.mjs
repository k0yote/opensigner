import { execFileSync } from 'node:child_process'
import NodeFS from 'node:fs'
import NodePath from 'node:path'
import Process from 'node:process'
import { SITE_URL, collectRoutes, findDistRoot, isIndexableRoute } from './dist.mjs'

// Emits sitemap.xml and robots.txt into the built output.
//
// Routes come from the HTML the build actually produced, not from the files under
// src/pages. Those two sets differ: the OpenAPI integration generates a page per
// resource tag, so a source-file walk misses a third of the site. Reading the build
// output means any route the framework invents is included without this script
// needing to know how it was produced.
//
// Vocs emits these itself only when `baseUrl` is set, but `baseUrl` also injects a
// <base> tag that resolves every relative asset against the production domain,
// which breaks hydration on local and preview origins. Writing the two files here
// keeps absolute SEO URLs without that tag.
const distRoot = findDistRoot('generate-seo-files')

// lastmod tracks the last commit touching the content behind a route, not the
// build clock. Stamping build time advertises every page as freshly changed on
// every deploy, which teaches crawlers to ignore the signal.
function gitDate(file) {
  if (!NodeFS.existsSync(file)) return undefined
  try {
    const out = execFileSync('git', ['log', '-1', '--format=%cs', '--', file], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
    if (out) return out
  } catch {
    // Not a git checkout, or the file is untracked.
  }
  return NodeFS.statSync(file).mtime.toISOString().slice(0, 10)
}

function lastModified(route) {
  const pagesDir = NodePath.join(Process.cwd(), 'src', 'pages')

  // Generated API reference routes trace back to their OpenAPI document.
  const api = route.match(/^\/apis\/([^/]+)/)
  if (api) {
    const spec = NodePath.join(Process.cwd(), 'public', 'swagger', `${api[1]}.yaml`)
    const fromSpec = gitDate(spec)
    if (fromSpec) return fromSpec
  }

  for (const ext of ['.mdx', '.md', '.tsx']) {
    const candidates =
      route === '/'
        ? [NodePath.join(pagesDir, `index${ext}`)]
        : [
            NodePath.join(pagesDir, `${route.slice(1)}${ext}`),
            NodePath.join(pagesDir, route.slice(1), `index${ext}`),
          ]
    for (const file of candidates) {
      const date = gitDate(file)
      if (date) return date
    }
  }
  return undefined
}

const routes = collectRoutes(distRoot).filter(isIndexableRoute).sort()

if (routes.length === 0) {
  throw new Error(`generate-seo-files: no routes found under ${distRoot}`)
}

const sitemap = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
  ...routes.map((route) => {
    const loc = route === '/' ? `${SITE_URL}/` : `${SITE_URL}${route}`
    const lastmod = lastModified(route)
    return [
      '  <url>',
      `    <loc>${loc}</loc>`,
      ...(lastmod ? [`    <lastmod>${lastmod}</lastmod>`] : []),
      '  </url>',
    ].join('\n')
  }),
  '</urlset>',
  '',
].join('\n')

// Advertise the llms.txt files alongside the sitemap. Vocs emits llms.txt,
// llms-full.txt, and a per-page markdown mirror under /assets/md; pointing at them
// from robots.txt is how an agent that starts at the root discovers there is a
// plain-text rendering it should prefer over scraping HTML.
const robots = [
  'User-agent: *',
  'Allow: /',
  '',
  `Sitemap: ${SITE_URL}/sitemap.xml`,
  '',
  '# Plain-text renderings for LLM and agent consumption:',
  `#   ${SITE_URL}/llms.txt       - index of pages with descriptions`,
  `#   ${SITE_URL}/llms-full.txt  - full documentation in one file`,
  `#   ${SITE_URL}/assets/md/     - per-page markdown`,
  '',
].join('\n')

NodeFS.writeFileSync(NodePath.join(distRoot, 'sitemap.xml'), sitemap)
NodeFS.writeFileSync(NodePath.join(distRoot, 'robots.txt'), robots)

console.log(`generate-seo-files: wrote sitemap.xml (${routes.length} routes) + robots.txt`)
