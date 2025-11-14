import { useState } from 'react'
import { Navbar, Sidebar } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { FileScanPage } from './pages/FileScanPage'
import { URLTestPage } from './pages/URLTestPage'
import './index.css'

export default function App() {
  const [currentPage, setCurrentPage] = useState('dashboard')
  
  return (
    <div className="flex flex-col h-screen bg-gray-950">
      <Navbar onNavigate={setCurrentPage} />
      
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        
        <div className="flex-1 overflow-auto">
          {currentPage === 'dashboard' && <Dashboard />}
          {currentPage === 'file-scan' && <FileScanPage />}
          {currentPage === 'url-test' && <URLTestPage />}
        </div>
      </div>
    </div>
  )
}
