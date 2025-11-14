export const Card = ({ children, className = '' }) => (
  <div className={`bg-gray-925 border border-gray-800 rounded-lg p-4 ${className}`}>
    {children}
  </div>
)

export const Badge = ({ children, variant = 'default', className = '' }) => {
  const variants = {
    default: 'bg-gray-800 text-gray-300',
    danger: 'bg-red-900/30 text-red-400 border border-red-700/50',
    warning: 'bg-yellow-900/30 text-yellow-400 border border-yellow-700/50',
    success: 'bg-green-900/30 text-green-400 border border-green-700/50',
    info: 'bg-blue-900/30 text-blue-400 border border-blue-700/50',
  }
  
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${variants[variant]} ${className}`}
    >
      {children}
    </span>
  )
}

export const Skeleton = ({ className = '' }) => (
  <div className={`skeleton rounded ${className}`} />
)

export const LoadingSpinner = () => (
  <div className="flex items-center justify-center">
    <div className="animate-spin">
      <div className="h-8 w-8 border-4 border-blue-500 border-t-transparent rounded-full" />
    </div>
  </div>
)

export const StatusDot = ({ status = 'success' }) => {
  const colors = {
    success: 'bg-green-500',
    warning: 'bg-yellow-500',
    danger: 'bg-red-500',
    neutral: 'bg-gray-500',
  }
  
  return (
    <div className={`w-2.5 h-2.5 rounded-full ${colors[status]} pulse-dot`} />
  )
}

export const Tooltip = ({ children, text, position = 'top' }) => (
  <div className="group relative inline-block">
    {children}
    <div
      className={`absolute bg-gray-900 text-white text-xs rounded px-2 py-1 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none ${
        position === 'top' ? 'bottom-full mb-2' : 'top-full mt-2'
      }`}
    >
      {text}
    </div>
  </div>
)
