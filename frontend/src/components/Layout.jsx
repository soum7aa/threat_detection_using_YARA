import { useEffect, useState } from 'react'
import { Card, Badge, StatusDot, Skeleton } from './ui'
import { useEventStore } from '../store'
import { apiClient } from '../api'

export const Navbar = ({ onNavigate }) => {
  const { connected, paused, setConnected } = useEventStore()
  
  const handleConnect = () => {
    if (connected) {
      // Disconnect
      setConnected(false)
      // Would close SSE here
    } else {
      // Connect
      setConnected(true)
      // Would start SSE here
    }
  }
  
  return (
    <header className="bg-gradient-to-b from-gray-925 to-gray-950/50 border-b border-gray-800 sticky top-0 z-50">
      <div className="px-6 py-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-red-600 to-red-800 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold">🛡️</span>
            </div>
            <h1 className="text-2xl font-bold text-white">AURA</h1>
            <span className="text-xs text-gray-500">
              Adaptive Unified Real-time Analyzer
            </span>
          </div>
          
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <StatusDot status={connected ? 'success' : 'neutral'} />
              <span className="text-sm text-gray-400">
                {connected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            <button
              onClick={handleConnect}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded"
            >
              {connected ? 'Disconnect' : 'Connect'}
            </button>
          </div>
        </div>
        
        <div className="flex gap-2">
          {['dashboard', 'file-scan', 'url-test'].map((page) => (
            <button
              key={page}
              onClick={() => onNavigate(page)}
              className="px-3 py-1.5 text-sm rounded bg-gray-900 hover:bg-gray-800 text-gray-300 hover:text-white"
            >
              {page === 'dashboard'
                ? '📊 Dashboard'
                : page === 'file-scan'
                  ? '📄 File Scan'
                  : '🔍 URL Test'}
            </button>
          ))}
        </div>
      </div>
    </header>
  )
}

export const Sidebar = () => {
  const [stats, setStats] = useState({
    totalIncidents: 0,
    yaraStatus: 'loading',
  })
  
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await apiClient.yaraStatus()
        setStats((s) => ({ ...s, yaraStatus: res.data.engine }))
      } catch (e) {
        console.error('Failed to fetch YARA status:', e)
      }
    }
    
    fetchStats()
  }, [])
  
  return (
    <aside className="hidden lg:flex w-64 bg-gray-925 border-r border-gray-800 flex-col h-screen sticky top-0">
      <div className="flex-1 p-4 overflow-y-auto">
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-4">
          System Status
        </p>
        
        <Card className="mb-4">
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-gray-400">YARA Engine</span>
              <Badge variant={stats.yaraStatus === 'yara' ? 'success' : 'warning'}>
                {stats.yaraStatus === 'yara'
                  ? '✓ Active'
                  : stats.yaraStatus === 'fallback'
                    ? '⚡ Fallback'
                    : '...'}
              </Badge>
            </div>
          </div>
        </Card>
        
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-4">
          Quick Actions
        </p>
        
        <div className="space-y-2">
          <button className="w-full px-3 py-2 text-left text-sm rounded bg-gray-900 hover:bg-gray-800 text-gray-300 hover:text-white">
            Reload YARA Rules
          </button>
          <button className="w-full px-3 py-2 text-left text-sm rounded bg-gray-900 hover:bg-gray-800 text-gray-300 hover:text-white">
            Manage Paths
          </button>
          <button className="w-full px-3 py-2 text-left text-sm rounded bg-gray-900 hover:bg-gray-800 text-gray-300 hover:text-white">
            Start Full Scan
          </button>
        </div>
      </div>
    </aside>
  )
}
