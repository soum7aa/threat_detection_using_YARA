import { useState } from 'react'
import { Card, Badge, LoadingSpinner } from './ui'
import { apiClient } from '../api'

export const FileScanPage = () => {
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  
  const handleFileSelect = (e) => {
    const selected = e.target.files?.[0]
    if (selected) {
      setFile(selected)
      setResult(null)
      setError(null)
    }
  }
  
  const handleScan = async () => {
    if (!file) return
    
    setLoading(true)
    setError(null)
    setResult(null)
    
    try {
      const res = await apiClient.uploadScan(file)
      if (res.data.status === 'ok') {
        setResult(res.data)
      } else {
        setError(res.data.error || 'Scan failed')
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Scan failed')
    } finally {
      setLoading(false)
    }
  }
  
  const formatBytes = (bytes) => {
    if (!bytes) return '-'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
    return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`
  }
  
  return (
    <div className="min-h-screen bg-gray-950 p-6">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-3xl font-bold text-white mb-2">File Scan</h1>
        <p className="text-gray-400 mb-6">Upload a file to analyze with YARA and heuristics.</p>
        
        <Card className="mb-6">
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <input
                type="file"
                onChange={handleFileSelect}
                className="flex-1 px-3 py-2 bg-gray-900 border border-gray-800 rounded text-white"
              />
              <button
                onClick={handleScan}
                disabled={!file || loading}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 text-white rounded font-medium"
              >
                {loading ? 'Scanning...' : 'Scan'}
              </button>
            </div>
            
            {file && !result && !loading && (
              <div className="text-sm text-gray-400">
                <p>
                  <span className="text-gray-500">File:</span> {file.name}
                </p>
                <p>
                  <span className="text-gray-500">Size:</span> {formatBytes(file.size)}
                </p>
              </div>
            )}
          </div>
        </Card>
        
        {loading && (
          <Card className="flex items-center justify-center py-12">
            <LoadingSpinner />
          </Card>
        )}
        
        {error && (
          <Card className="bg-red-900/20 border-red-700/50">
            <p className="text-red-400">Error: {error}</p>
          </Card>
        )}
        
        {result && !loading && (
          <div className="space-y-4">
            <Card>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-white">Scan Results</h2>
                <Badge
                  variant={
                    result.verdict === 'suspicious'
                      ? 'danger'
                      : result.verdict === 'clean'
                        ? 'success'
                        : 'warning'
                  }
                >
                  {result.verdict?.toUpperCase()}
                </Badge>
              </div>
              
              <div className="grid grid-cols-2 gap-4 mb-4 text-sm text-gray-400">
                <div>
                  <span className="text-gray-500">File:</span> {result.file?.name}
                </div>
                <div>
                  <span className="text-gray-500">Size:</span>{' '}
                  {formatBytes(result.file?.size)}
                </div>
                <div>
                  <span className="text-gray-500">Type:</span> {result.file?.type}
                </div>
                <div>
                  <span className="text-gray-500">MIME:</span>{' '}
                  {result.file?.mime_type}
                </div>
              </div>
              
              {result.file?.sha256 && (
                <p className="text-xs text-gray-500 break-all font-mono mb-4">
                  SHA256: {result.file.sha256}
                </p>
              )}
              
              {result.scan_steps && result.scan_steps.length > 0 && (
                <div className="mb-4">
                  <p className="text-xs font-semibold text-gray-400 mb-2">Scan Steps:</p>
                  <div className="flex flex-wrap gap-2">
                    {result.scan_steps.map((step) => (
                      <Badge key={step} variant="default">
                        {step}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </Card>
            
            {result.yara && result.yara.length > 0 && (
              <Card className="bg-red-900/10 border-red-700/30">
                <p className="text-sm font-semibold text-red-400 mb-2">
                  YARA Matches ({result.yara.length})
                </p>
                <div className="flex flex-wrap gap-2">
                  {result.yara.map((rule, i) => (
                    <Badge key={i} variant="danger">
                      {rule}
                    </Badge>
                  ))}
                </div>
              </Card>
            )}
            
            {result.heuristics && result.heuristics.length > 0 && (
              <Card className="bg-yellow-900/10 border-yellow-700/30">
                <p className="text-sm font-semibold text-yellow-400 mb-2">
                  Suspicious Patterns ({result.heuristics.length})
                </p>
                <ul className="space-y-1 text-sm text-gray-400">
                  {result.heuristics.map((h, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-yellow-500">•</span>
                      <span>{h}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            )}
            
            {result.analysis && result.analysis.length > 0 && (
              <Card>
                <p className="text-sm font-semibold text-gray-400 mb-2">
                  Analysis Notes
                </p>
                <ul className="space-y-1 text-sm text-gray-400">
                  {result.analysis.map((note, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-blue-500">ℹ</span>
                      <span>{note}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            )}
            
            {result.inner_hits && result.inner_hits.length > 0 && (
              <Card className="bg-orange-900/10 border-orange-700/30">
                <p className="text-sm font-semibold text-orange-400 mb-2">
                  Inner File Findings
                </p>
                <ul className="space-y-2 text-sm text-gray-400">
                  {result.inner_hits.map((hit, i) => (
                    <li key={i} className="border-l-2 border-orange-500/30 pl-2">
                      <p className="font-semibold text-orange-300">{hit.name}</p>
                      <p className="text-xs">Verdict: {hit.verdict}</p>
                    </li>
                  ))}
                </ul>
              </Card>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
