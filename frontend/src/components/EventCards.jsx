import { Card, Badge, StatusDot } from './ui'

export const ProcessEventCard = ({ event, onKill, onQuarantine }) => {
  const { event: ev, detection, yara } = event
  const isSuspicious = yara?.length > 0 || detection?.label === -1
  const severity = yara?.length ? 'danger' : detection?.label === -1 ? 'warning' : 'default'
  
  return (
    <Card className="fade-in">
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <StatusDot status={isSuspicious ? 'danger' : 'success'} />
          <div>
            <h4 className="font-semibold text-white">{ev.name || 'Process'}</h4>
            <p className="text-xs text-gray-400">PID {ev.pid}</p>
          </div>
        </div>
        {isSuspicious && <Badge variant={severity}>SUSPICIOUS</Badge>}
      </div>
      
      <div className="grid grid-cols-2 gap-2 mb-3 text-sm text-gray-400">
        <div>
          <span className="text-gray-500">CPU:</span> {(ev.cpu_percent?.toFixed(1) || 0)}%
        </div>
        <div>
          <span className="text-gray-500">Memory:</span> {(ev.mem_percent?.toFixed(1) || 0)}%
        </div>
      </div>
      
      {ev.exe && (
        <p className="text-xs text-gray-500 break-all mb-2 font-mono">
          {ev.exe}
        </p>
      )}
      
      {ev.cmdline && (
        <p className="text-xs text-gray-500 break-all mb-3 font-mono line-clamp-2">
          {ev.cmdline}
        </p>
      )}
      
      {yara && yara.length > 0 && (
        <div className="mb-2">
          <p className="text-xs font-semibold text-red-400 mb-1">YARA:</p>
          <div className="flex flex-wrap gap-1">
            {yara.map((rule, i) => (
              <Badge key={i} variant="danger" className="text-xs">
                {rule}
              </Badge>
            ))}
          </div>
        </div>
      )}
      
      <div className="flex gap-2 mt-3">
        <button
          onClick={() => onKill(ev.pid)}
          className="text-xs px-2 py-1 bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded"
        >
          Kill Process
        </button>
        {ev.exe && (
          <button
            onClick={() => onQuarantine(ev.exe)}
            className="text-xs px-2 py-1 bg-yellow-600/20 hover:bg-yellow-600/40 text-yellow-400 rounded"
          >
            Quarantine
          </button>
        )}
      </div>
    </Card>
  )
}

export const NetworkEventCard = ({ event, onQuarantine }) => {
  const { event: ev, yara } = event
  const isSuspicious = ev.is_suspicious || yara?.length > 0
  
  return (
    <Card className="fade-in">
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <StatusDot status={isSuspicious ? 'danger' : ev.is_browsing ? 'info' : 'success'} />
          <div>
            <h4 className="font-semibold text-white">
              {ev.is_browsing ? '🌐 Browsing' : 'Network Connection'}
            </h4>
            <p className="text-xs text-gray-400">PID {ev.pid}</p>
          </div>
        </div>
        {isSuspicious && <Badge variant="danger">SUSPICIOUS</Badge>}
      </div>
      
      <div className="space-y-1 text-sm text-gray-400 mb-2 font-mono text-xs">
        <div>
          <span className="text-gray-500">Status:</span> {ev.status}
        </div>
        <div>
          <span className="text-gray-500">Local:</span> {ev.laddr?.ip}:{ev.laddr?.port}
        </div>
        <div>
          <span className="text-gray-500">Remote:</span> {ev.raddr?.ip}:{ev.raddr?.port}
        </div>
        {ev.remote_hostname && (
          <div>
            <span className="text-gray-500">Domain:</span> {ev.remote_hostname}
          </div>
        )}
      </div>
      
      {ev.suspicious_reason && (
        <div className="text-xs text-red-400 mb-2">{ev.suspicious_reason}</div>
      )}
      
      {yara && yara.length > 0 && (
        <div className="mb-2">
          <p className="text-xs font-semibold text-red-400 mb-1">YARA:</p>
          <div className="flex flex-wrap gap-1">
            {yara.map((rule, i) => (
              <Badge key={i} variant="danger" className="text-xs">
                {rule}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}

export const FileEventCard = ({ event, onQuarantine }) => {
  const { event: ev, yara } = event
  const isSuspicious = yara?.length > 0
  
  return (
    <Card className="fade-in">
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <StatusDot status={isSuspicious ? 'danger' : 'success'} />
          <div>
            <h4 className="font-semibold text-white">
              File {ev.subtype || 'Event'}
            </h4>
          </div>
        </div>
        {isSuspicious && <Badge variant="danger">SUSPICIOUS</Badge>}
      </div>
      
      <p className="text-xs text-gray-500 break-all mb-2 font-mono">
        {ev.path}
      </p>
      
      {yara && yara.length > 0 && (
        <div className="mb-2">
          <p className="text-xs font-semibold text-red-400 mb-1">YARA:</p>
          <div className="flex flex-wrap gap-1">
            {yara.map((rule, i) => (
              <Badge key={i} variant="danger" className="text-xs">
                {rule}
              </Badge>
            ))}
          </div>
        </div>
      )}
      
      {ev.path && (
        <button
          onClick={() => onQuarantine(ev.path)}
          className="text-xs px-2 py-1 bg-yellow-600/20 hover:bg-yellow-600/40 text-yellow-400 rounded"
        >
          Quarantine File
        </button>
      )}
    </Card>
  )
}
