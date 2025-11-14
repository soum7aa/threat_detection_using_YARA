# AURA React Frontend

Modern React + Vite + TailwindCSS frontend for the Adaptive Unified Real-time Analyzer.

## Setup

```bash
cd frontend
npm install
npm run dev
```

The dev server proxies API calls to `http://127.0.0.1:5000`. Make sure the Flask backend is running.

## Build

```bash
npm run build
```

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

## Environment

Set `VITE_API_BASE` to override the backend URL (defaults to `http://127.0.0.1:5000`).
