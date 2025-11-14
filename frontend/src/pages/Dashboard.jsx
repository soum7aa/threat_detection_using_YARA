import { useEffect, useState } from 'react'
import { Card, Badge, Skeleton } from './ui'
import { ProcessEventCard, NetworkEventCard, FileEventCard } from './EventCards'
import { useEventStore } from '../store'
import { apiClient } from '../api'

export const Dashboard = () => {
  const {
    processEvents,
    networkEvents,
    fileEvents,
    incidents,
    connected,
    paused,
    filterSuspicious,
    searchQuery,
    addEvent,
    setIncidents,
    setConnected,
    setPaused,
    setFilterSuspicious,
    setSearchQuery,
    clearEvents,
  } = useEventStore()
  
  const [activeTab, setActiveTab] = useState('process')
  const [loading, setLoading] = useState(false)
  
  // SSE subscription
  useEffect(() => {
    if (!connected) return
    
    setLoading(true)
    const eventSource = new EventSource('/api/stream')
    
    eventSource.onopen = () => {
      setLoading(false)
    }
    
    eventSource.onmessage = (event) => {
      if (paused) return
      try {
        const obj = JSON.parse(event.data)
        addEvent(obj)
      } catch (e) {
        console.error('Failed to parse event:', e)
      }
    }
    
    eventSource.onerror = () => {
      setConnected(false)
      eventSource.close()
    }
    
    return () => {
      eventSource.close()
    }
  }, [connected, paused, addEvent, setConnected])
  
  // Load incidents on mount
  useEffect(() => {
    const loadIncidents = async () => {
      try {
        const res = await apiClient.incidents()
        setIncidents(res.data || [])
      } catch (e) {
        console.error('Failed to load incidents:', e)
      }
    }
    
    loadIncidents()
  }, [setIncidents])
  
  const handleMitigate = async (action, payload) => {
    try {
      await apiClient.mitigate(action, payload)
      alert(`Action '${action}' completed.`)
    } catch (e) {
      alert(`Failed: ${e.message}`)
    }
  }
  
  const filterEvents = (events) => {
    return events.filter((e) => {
      const ev = e.event || {}
      const text = [
        ev.name,
        ev.cmdline,
        ev.exe,
        ev.path,
        ev.remote_hostname,
        ev.suspicious_reason,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      
      if (searchQuery && !text.includes(searchQuery.toLowerCase())) return false
      
      if (filterSuspicious) {
        const isSuspicious =
          (e.yara?.length > 0) || (e.detection?.label === -1) || ev.is_suspicious
        if (!isSuspicious) return false
      }
      
      return true
    })
  }
  
  const tabContent = {
    process: filterEvents(processEvents),
    network: filterEvents(networkEvents),
    file: filterEvents(fileEvents),
  }
  
  return (
    <div className="flex flex-col lg:flex-row gap-6 h-screen overflow-hidden">
      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Toolbar */}
        <div className="px-6 py-4 border-b border-gray-800">
          <div className="flex items-center gap-2 mb-4">
            <button
              onClick={() => (connected ? clearEvents() : setConnected(true))}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded"
            >
              {connected ? 'Clear' : 'Connect'}
            </button>
            <button
              onClick={() => setPaused(!paused)}
              className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-white text-sm rounded"
            >
              {paused ? 'Resume' : 'Pause'}
            </button>
            <button
              onClick={() => setFilterSuspicious(!filterSuspicious)}
              className={`px-3 py-1.5 text-sm rounded ${
                filterSuspicious
                  ? 'bg-red-600 text-white'
                  : 'bg-gray-800 text-gray-300'
              }`}
            >
              Suspicious Only
            </button>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search..."
              className="flex-1 px-3 py-1.5 bg-gray-900 border border-gray-800 rounded text-white placeholder-gray-500 text-sm"
            />
          </div>
          
          {/* Tabs */}
          <div className="flex gap-2">
            {['process', 'network', 'file'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1.5 text-xs rounded font-medium ${
                  activeTab === tab
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-800 text-gray-400'
                }`}
              >
                {tab === 'process'
                  ? `Process (${tabContent.process.length})`
                  : tab === 'network'
                    ? `Network (${tabContent.network.length})`
                    : `File (${tabContent.file.length})`}
              </button>
            ))}
          </div>
        </div>
        
        {/* Event list */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-2">
          {loading && (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-32 rounded" />
              ))}
            </div>
          )}
          
          {!loading && tabContent[activeTab].length === 0 && (
            <Card className="text-center py-8">
              <p className="text-gray-500">
                {connected
                  ? 'No events yet. Waiting for activity...'
                  : 'Connect to view live events.'}
              </p>
            </Card>
          )}
          
          {activeTab === 'process' &&
            tabContent.process.map((e, i) => (
              <ProcessEventCard
                key={i}
                event={e}
                onKill={(pid) => handleMitigate('kill_process', { pid })}
                onQuarantine={(path) =>
                  handleMitigate('quarantine_file', { path })
                }
              />
            ))}
          
          {activeTab === 'network' &&
            tabContent.network.map((e, i) => (
              <NetworkEventCard
                key={i}
                event={e}
                onQuarantine={(path) =>
                  handleMitigate('quarantine_file', { path })
                }
              />
            ))}
          
          {activeTab === 'file' &&
            tabContent.file.map((e, i) => (
              <FileEventCard
                key={i}
                event={e}
                onQuarantine={(path) =>
                  handleMitigate('quarantine_file', { path })
                }
              />
            ))}
        </div>
      </div>
      
      {/* Incidents sidebar */}
      <div className="hidden lg:flex w-96 bg-gray-925 border-l border-gray-800 flex-col">
        <div className="px-4 py-4 border-b border-gray-800">
          <h2 className="font-semibold text-white">
            Incidents ({incidents.length})
          </h2>
          <p className="text-xs text-gray-500">Stored suspicious events</p>
        </div>
        
        <div className="flex-1 overflow-y-auto space-y-2 p-4">
          {incidents.length === 0 && (
            <Card className="text-center py-6">
              <p className="text-gray-500 text-sm">No incidents yet.</p>
            </Card>
          )}
          
          {incidents.map((inc, i) => (
            <Card key={i} className="text-xs">
              <div className="flex items-start justify-between mb-1">
                <span className="font-semibold text-white">Incident</span>
                {inc.yara && <Badge variant="danger">YARA</Badge>}
              </div>
              <p className="text-gray-500 truncate">
                {inc.event?.name || inc.event?.type}
              </p>
              {inc.mitre && inc.mitre.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {inc.mitre.slice(0, 3).map((m, j) => (
                    <Badge key={j} variant="warning">
                      {m.technique_id}
                    </Badge>
                  ))}
                </div>
              )}
            </Card>
          ))}
        </div>
      </div>
    </div>
  )
}
