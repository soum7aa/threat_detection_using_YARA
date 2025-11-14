# AURA React Frontend

Modern React + Vite + TailwindCSS frontend for the Adaptive Unified Real-time Analyzer.

## Setup

```bash
cd frontend
npm install
```

Create a `.env` file (copy from `.env.example`):

```bash
cp .env.example .env
```

Start the dev server:

```bash
npm run dev
```

The dev server runs on `http://127.0.0.1:5173` and proxies `/api` requests to the Flask backend at `http://127.0.0.1:5000` via Vite's dev proxy (see `vite.config.js`). Make sure the backend is running before starting the frontend.

## Build & Deployment

```bash
npm run build
```

Creates optimized build in `dist/`. To serve via Flask:

```bash
rm -rf ../static/*
cp -r dist/* ../static/
cd ..
python run_integrated_system.py
```

Access the app at `http://127.0.0.1:5000` (frontend and API on same host, no CORS issues).

## Features

- **Live Monitoring**: Real-time SSE stream of process, network, and file events
- **File Scanning**: Upload and analyze files with YARA, heuristics, and macro detection
- **URL Safety Testing**: Test URLs for malicious patterns and phishing indicators
- **Incident Tracking**: View stored incidents with MITRE ATT&CK mappings
- **Dark Theme**: Polished dark UI with animations and loading states
- **Responsive Design**: Sidebar + navbar layout with mobile support

## Architecture

- **State**: Zustand for event/incident management
- **API**: Axios with configured backend proxy
- **Components**: Reusable Card, Badge, EventCard, Skeleton, LoadingSpinner, Tooltip
- **Pages**: Dashboard, FileScanPage, URLTestPage

## Environment Variables

- `VITE_API_BASE`: Backend API base URL
  - Default: `http://127.0.0.1:5000`
  - **Recommended for dev**: `/api` (uses Vite proxy, avoids CORS)
  - Use full URL if backend is on a different host

See `.env.example` for a template.
