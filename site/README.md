# ReproAssert public site

This directory contains the one-route public proof surface for ReproAssert. It
uses the Sites vinext runtime and intentionally has no dashboard, persistence,
authentication, or server-side product API.

## Local development

Requirements: Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

Build and verify the server-rendered contract:

```bash
npm run build
node --test tests/rendered-html.test.mjs
```

The generated `.openai/hosting.json`, `vite.config.ts`, worker, and Sites Vite
plugin are runtime infrastructure. Keep them intact when changing the page.

## Public-claim rules

- The CLI claim ceiling is `repeatable_base_failure`.
- Benchmark v0.1 has 20 frozen cases and 0 scored result rows.
- The local Docker fixture is not benchmark or maintainer evidence.
- The $10,000 MRR path is customer math, not a forecast or published offer.
- Do not add fake metrics, customers, testimonials, logos, or success claims.

Product, security, evaluation, and business details live in the repository root
documentation.
