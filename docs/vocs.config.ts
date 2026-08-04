import { OpenApi, defineConfig } from 'vocs/config'

import { sidebar } from './sidebar'

export default defineConfig({
  // Native OpenAPI integration, replacing an embedded swagger-ui-react viewer.
  //
  // The distinction that matters is prerendering. A client-rendered viewer fetches
  // its spec in the browser, so none of the endpoint documentation exists in the
  // built HTML: search engines and the llms.txt/markdown output saw an empty page
  // where the API reference should be. These routes are generated at build time,
  // so every operation is in the HTML and in the markdown mirror.
  openapi: [
    OpenApi.from({ spec: './public/swagger/auth_service.yaml', path: '/apis/auth_service' }),
    OpenApi.from({ spec: './public/swagger/hot_storage.yaml', path: '/apis/hot_storage' }),
    OpenApi.from({ spec: './public/swagger/cold_storage.yaml', path: '/apis/cold_storage' }),
  ],
  // Fails the build on a link to a page that does not exist. This covers the page
  // half of an internal link only -- the `#fragment` half is checked separately by
  // scripts/check-anchors.mjs, which resolves it against the rendered HTML.
  checkDeadlinks: true,
  title: 'OpenSigner | Non-Custodial Wallet Key Management',
  titleTemplate: '%s – OpenSigner',
  description: 'Open-source, non-custodial, self-hostable private key management.',
  logoUrl: {
    light: '/icons/open-signer-logo.svg',
    dark: '/icons/open-signer-logo.svg',
  },
  iconUrl: '/icons/icon.svg',
  banner: 'If you like OpenSigner, give it a [star on GitHub ⭐](https://github.com/openfort-xyz/opensigner)!',
  ogImageUrl: 'https://www.opensigner.dev/og-image.png',
  accentColor: '#004AAD',
  renderStrategy: 'full-static',
  sidebar,
  topNav: [
    { text: 'Guides & API', link: '/introduction/setup' },
    {
      text: 'Contributing',
      link: 'https://github.com/openfort-xyz/opensigner?tab=contributing-ov-file',
    },
  ],
  socials: [
    { icon: 'github', link: 'https://github.com/openfort-xyz/opensigner' },
    { icon: 'telegram', link: 'https://t.me/openfort' },
    { icon: 'x', link: 'https://x.com/openfort_hq' },
  ],
})
