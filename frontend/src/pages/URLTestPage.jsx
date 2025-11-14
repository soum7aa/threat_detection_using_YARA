import { useState } from 'react'
import { Card, Badge, LoadingSpinner } from './ui'
import { apiClient } from '../api'

export const URLTestPage = () => {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [deepAnalysis, setDeepAnalysis] = useState(true)
  
  const handleTest = async () => {
    if (!url.trim()) return
    
    setLoading(true)
    setError(null)
    setResult(null)
    
    try {
      const res = await apiClient.testUrl(url, deepAnalysis)
      setResult(res.data)
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Test failed')
    } finally {
      setLoading(false)
    }
  }
  
  const getRatingColor = (rating) => {
    switch (rating) {
      case 'safe':
        return 'success'
      case 'warning':
        return 'warning'
      case 'danger':
        return 'danger'
      default:
        return 'default'
    }
  }
  
  return (
    <div className="min-h-screen bg-gray-950 p-6">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-3xl font-bold text-white mb-2">URL Safety Test</h1>
        <p className="text-gray-400 mb-6">
          Analyze websites for malicious content and suspicious patterns.
        </p>
        
        <Card className="mb-6">
          <div className="space-y-4">
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleTest()}
              placeholder="https://example.com"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-800 rounded text-white placeholder-gray-500"
            />
            
            <label className="flex items-center gap-2 text-sm text-gray-400">
              <input
                type="checkbox"
                checked={deepAnalysis}
                onChange={(e) => setDeepAnalysis(e.target.checked)}
                className="rounded"
              />
              Deep analysis (fetch page content)
            </label>
            
            <button
              onClick={handleTest}
              disabled={!url.trim() || loading}
              className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 text-white rounded font-medium"
            >
              {loading ? 'Testing...' : 'Test URL'}
            </button>
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
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h2 className="text-xl font-semibold text-white mb-1">
                    {result.url}
                  </h2>
                  <p className="text-sm text-gray-400">{result.domain}</p>
                </div>
                <Badge variant={getRatingColor(result.safety_rating)}>
                  {result.safety_rating?.toUpperCase()}
                </Badge>
              </div>
              
              <p className="text-sm text-gray-300 mb-3">
                {result.is_safe
                  ? '✅ This URL appears to be safe.'
                  : '🚨 This URL has suspicious characteristics. Proceed with caution.'}
              </p>
              
              {result.primary_category && (
                <p className="text-xs text-gray-500 mb-2">
                  <span className="text-gray-400">Category:</span> {result.primary_category}
                </p>
              )}
            </Card>
            
            {result.threats && result.threats.length > 0 && (
              <Card className="bg-red-900/10 border-red-700/30">
                <p className="text-sm font-semibold text-red-400 mb-2">
                  🚨 Threats ({result.threats.length})
                </p>
                <ul className="space-y-1 text-sm text-red-300">
                  {result.threats.map((t, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="mt-0.5">•</span>
                      <span>{t}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            )}
            
            {result.warnings && result.warnings.length > 0 && (
              <Card className="bg-yellow-900/10 border-yellow-700/30">
                <p className="text-sm font-semibold text-yellow-400 mb-2">
                  ⚠️ Warnings ({result.warnings.length})
                </p>
                <ul className="space-y-1 text-sm text-yellow-300">
                  {result.warnings.map((w, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="mt-0.5">•</span>
                      <span>{w}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            )}
            
            {result.details && result.details.length > 0 && (
              <Card>
                <p className="text-sm font-semibold text-gray-400 mb-2">
                  📋 Analysis Details
                </p>
                <ul className="space-y-1 text-sm text-gray-400">
                  {result.details.map((d, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-gray-500 mt-0.5">ℹ</span>
                      <span>{d}</span>
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
