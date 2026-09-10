# ZNexus Key System — stable base

This package keeps the stable single-page UI and connects it to the server-side Firebase/Vercel flow.

## Included
- `index.html` — stable UI/flow with protected API integration.
- `api/[...route].js` — Vercel backend with Firebase Admin.
- Atomic session/return handling to avoid refresh/replay state bugs.
- Server-side key issuance and validation.
- Linkvertise Anti-Bypassing verification when a valid provider hash is returned.
- Compatibility return-token flow for the current provider return behavior.
- Node 24.x configuration.

## Environment variables
Set these in Vercel:
- `FIREBASE_DATABASE_URL`
- `FIREBASE_SERVICE_ACCOUNT_JSON`
- `LINKVERTISE_ANTI_BYPASS_TOKEN`
- `AD_PROVIDER_BASE_URL`
- `PUBLIC_BASE_URL`

Do not place service-account credentials or private tokens in `index.html`.
