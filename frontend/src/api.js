import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:5000'

const api = axios.create({
  baseURL: `${API_BASE}/api`,
  timeout: 30000,
})

export const apiClient = {
  stream: () => new EventSource(`${API_BASE}/api/stream`),
  
  incidents: () => api.get('/incidents'),
  
  uploadScan: (file) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/upload_scan', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
  
  testUrl: (url, fetch = true) =>
    api.post('/test_url', { url, fetch }),
  
  mitigate: (action, payload) =>
    api.post('/mitigate', { action, ...payload }),
  
  yaraReload: () => api.post('/yara/reload'),
  yaraStatus: () => api.get('/yara/status'),
  
  paths: () => api.get('/paths'),
  updatePaths: (paths) => api.post('/paths', { paths }),
  
  scanStart: (settings) => api.post('/scan_paths/start', settings),
  scanStatus: () => api.get('/scan_paths/status'),
  scanCancel: () => api.post('/scan_paths/cancel'),
}
