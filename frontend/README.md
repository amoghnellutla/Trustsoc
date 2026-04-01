# TrustSOC Dashboard

React + TypeScript + Tailwind CSS frontend for the TrustSOC SOC automation platform.

## Pages

| Route | Description |
|-------|-------------|
| `/` | Overview — stat cards, severity chart, high-risk feed |
| `/alerts` | Alert feed — sortable table, filters, slide-out detail panel, inline feedback |
| `/incidents` | Incident cards grouped by pattern (brute force, lateral movement, privilege escalation) |
| `/mitre` | MITRE ATT&CK heatmap — color-intensity grid by technique |
| `/evidence` | Evidence viewer — tamper-proof audit trail with hash verification |

## Local development

```bash
# 1. Install dependencies
cd frontend
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env and set:
#   VITE_API_URL=https://trustsoc-api.onrender.com  (or http://localhost:8000 for local backend)
#   VITE_API_KEY=your-trustsoc-api-key

# 3. Start dev server
npm run dev
# Opens at http://localhost:3000
```

## Build for production

```bash
npm run build
# Output in dist/
```

## Deploy to Vercel (free tier)

1. Push the repo to GitHub
2. Go to [vercel.com](https://vercel.com) → New Project → Import your repo
3. Set **Root Directory** to `frontend`
4. Add environment variables:
   - `VITE_API_URL` = `https://trustsoc-api.onrender.com`
   - `VITE_API_KEY` = your API key
5. Deploy → gets a free `trustsoc-dashboard.vercel.app` URL

The `vercel.json` already handles SPA routing (rewrites `/*` to `/index.html`).

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_API_URL` | No | `https://trustsoc-api.onrender.com` | TrustSOC backend URL |
| `VITE_API_KEY` | Yes | — | TrustSOC `API_KEY` value |

## Tech stack

- **Vite** — build tool
- **React 18** — UI
- **TypeScript** — type safety
- **Tailwind CSS v3** — styling (dark theme, GitHub-style)
- **React Router v6** — routing
- **TanStack Query** — data fetching, caching, auto-refresh
- **Recharts** — charts
