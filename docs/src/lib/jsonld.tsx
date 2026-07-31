type JsonLdData = Record<string, unknown>

const SITE_URL = 'https://www.opensigner.dev'

export function techArticle(args: { headline: string; description: string; path: string }): JsonLdData {
  return {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: args.headline,
    description: args.description,
    url: `${SITE_URL}${args.path}`,
    isPartOf: { '@type': 'WebSite', name: 'OpenSigner', url: SITE_URL },
    publisher: { '@type': 'Organization', name: 'OpenSigner', url: SITE_URL },
  }
}

// JSON.stringify does not escape `<`, so a value containing `</script>` would
// close the surrounding tag and everything after it would be parsed as markup.
// Escaping to the < form keeps the JSON byte-identical in meaning while
// making that impossible. `&` and line separators are escaped for the same
// reason: they are valid in JSON but hazardous in an inline script context.
function serializeForScriptTag(value: JsonLdData): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029')
}

export function JsonLd({ data }: { data: JsonLdData | JsonLdData[] }) {
  const items = Array.isArray(data) ? data : [data]
  return (
    <>
      {items.map((item) => (
        <script
          key={JSON.stringify(item).slice(0, 64)}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: serializeForScriptTag(item) }}
        />
      ))}
    </>
  )
}
