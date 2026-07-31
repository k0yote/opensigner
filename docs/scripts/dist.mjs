import NodeFS from 'node:fs'
import NodePath from 'node:path'
import Process from 'node:process'

// Shared between the SEO generator and the build guardrails so they walk the
// build output identically; a checker with its own walker fails on pages its
// generator never considered.

export const SITE_URL = 'https://www.opensigner.dev'

export function findDistRoot(script) {
  const distRoot = ['dist/public', 'dist']
    .map((d) => NodePath.join(Process.cwd(), d))
    .find((d) => NodeFS.existsSync(NodePath.join(d, 'index.html')))
  if (!distRoot) {
    throw new Error(`${script}: no built output found — run \`vocs build\` first`)
  }
  return distRoot
}

// RSC payloads, hashed assets, and per-route .d directories are build
// machinery, not pages.
function isPageDirectory(name) {
  return name !== 'RSC' && name !== 'assets' && !name.endsWith('.d')
}

export function collectRoutes(dir, prefix = '') {
  const routes = []
  for (const entry of NodeFS.readdirSync(dir, { withFileTypes: true })) {
    const full = NodePath.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (!isPageDirectory(entry.name)) continue
      routes.push(...collectRoutes(full, `${prefix}/${entry.name}`))
      continue
    }
    if (!entry.name.endsWith('.html')) continue
    if (entry.name === 'index.html') routes.push(prefix || '/')
    else routes.push(`${prefix}/${entry.name.replace(/\.html$/, '')}`)
  }
  return routes
}

/** Page HTML files relative to distRoot, walked with the same skip rules. */
export function collectHtmlFiles(dir, prefix = '') {
  const files = []
  for (const entry of NodeFS.readdirSync(dir, { withFileTypes: true })) {
    const full = NodePath.join(dir, entry.name)
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) {
      if (!isPageDirectory(entry.name)) continue
      files.push(...collectHtmlFiles(full, rel))
      continue
    }
    if (entry.name.endsWith('.html')) files.push(rel)
  }
  return files
}

// 404 and the internal root layout are not indexable pages.
export function isIndexableRoute(route) {
  return !route.startsWith('/404') && !route.startsWith('/_root')
}
