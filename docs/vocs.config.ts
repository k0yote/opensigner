import { defineConfig } from 'vocs/config'

import { sidebar } from './sidebar'

export default defineConfig({
  baseUrl: 'https://opensigner.dev',
  title: 'OpenSigner | Non-Custodial Wallet Key Management',
  description: 'Open-source and non-custodial and self-hostable private key management.',
  logoUrl: {
    light: '/icons/open-signer-logo.svg',
    dark: '/icons/open-signer-logo.svg',
  },
  iconUrl: '/icons/icon.svg',
  banner: 'If you like OpenSigner, give it a [star on GitHub ⭐](https://github.com/openfort-xyz/opensigner)!',
  ogImageUrl: 'https://opensigner.dev/og-image.png',
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
