#!/usr/bin/env node

// lychee `--preprocess` hook: prints a source file with its internal link targets
// blanked, so the link job reports external rot only.
//
// Internal links belong to tools that understand the routing: Vocs' `checkDeadlinks`
// resolves the page and `check:anchors` resolves the `#fragment`. A generic checker
// cannot -- it maps a URL path onto the filesystem, but `/security/overview` is
// `src/pages/security/overview.mdx`. Left in, every one of them is reported as a
// missing file, and that volume of noise is how a check gets ignored.
//
// The same applies to props that are not links at all: an `src` holding an id or a
// template placeholder reads to a checker as a relative path.
//
// A target is external exactly when it carries a URI scheme, so everything else
// becomes `#` -- replaced rather than removed, so the surrounding Markdown still
// parses and line numbers in any report still line up.

import NodeFS from 'node:fs'
import Process from 'node:process'

/** `https:`, `mailto:`, `tel:` — anything a checker can actually request. */
const uriScheme = /^[a-z][a-z0-9+.-]*:/i
/** `](target)` and `](<target with spaces>)` destinations. */
const markdownDestination = /(\]\()(<[^>\n]*>|[^\s)]*)/g
/** `[label]: target` reference definitions. */
const markdownDefinition = /(^[\t ]*\[[^\]]+\]:[\t ]*)(<[^>\n]*>|\S+)/gm
/** `href`, `src` and `link` props, quoted or as a `{expression}`. */
const linkAttribute = /\b(href|src|link)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{[^}]*\})/g

function isExternal(target) {
  return uriScheme.test(target.replace(/^<|>$/g, '').trim())
}

export function externalLinkSource(source) {
  return source
    .replace(markdownDestination, (match, open, target) => (isExternal(target) ? match : `${open}#`))
    .replace(markdownDefinition, (match, open, target) => (isExternal(target) ? match : `${open}#`))
    .replace(linkAttribute, (match, name, doubleQuoted, singleQuoted) => {
      const target = doubleQuoted ?? singleQuoted
      // An expression has no static target to check.
      if (target === undefined) return `${name}="#"`
      return isExternal(target) ? match : `${name}="#"`
    })
}

const file = Process.argv[2]
if (!file) throw new Error('filter-external-links: expected a source file path')

Process.stdout.write(externalLinkSource(NodeFS.readFileSync(file, 'utf8')))
