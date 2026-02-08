import { useState, useEffect } from 'react'
import ApplicationCard from './components/ApplicationCard'
import './App.css'

function App() {
  const [applications, setApplications] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    async function fetchApplications() {
      try {
        setLoading(true)
        setError(null)
        const res = await fetch('/api/applications', {
          headers: {
            'X-AD-Groups': '', // Dev: empty = show all; Prod: ADFS will provide
          },
        })
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        setApplications(data.applications || [])
      } catch (err) {
        setError(err.message)
        setApplications([])
      } finally {
        setLoading(false)
      }
    }
    fetchApplications()
  }, [])

  return (
    <div className="app">
      <header className="app-header">
        <h1>Frodo</h1>
        <p className="app-subtitle">Firewall Operations & Definition Orchestration</p>
      </header>

      <main className="app-main">
        {loading && (
          <div className="app-loading">Loading applications…</div>
        )}
        {error && (
          <div className="app-error">
            Failed to load applications: {error}
          </div>
        )}
        {!loading && !error && applications.length === 0 && (
          <div className="app-empty">No applications found.</div>
        )}
        {!loading && !error && applications.length > 0 && (
          <div className="application-grid">
            {applications.map((app) => (
              <ApplicationCard key={`${app.business_application_name}-${app.environment}`} application={app} />
            ))}
          </div>
        )}
      </main>
    </div>
  )
}

export default App
