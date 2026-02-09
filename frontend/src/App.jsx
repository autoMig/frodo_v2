import { useState, useEffect } from 'react'
import ApplicationCard from './components/ApplicationCard'
import './App.css'

function useDebouncedValue(value, delay) {
  const [debouncedValue, setDebouncedValue] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debouncedValue
}

const ENVIRONMENT_OPTIONS = [
  { value: '', label: 'All environments' },
  { value: 'production', label: 'Production' },
  { value: 'uat', label: 'UAT' },
  { value: 'dev', label: 'Dev' },
  { value: 'oat', label: 'OAT' },
  { value: 'cont', label: 'Cont' },
]

const FIREWALL_OPTIONS = [
  { value: '', label: 'All firewalls' },
  { value: 'illumio', label: 'Illumio' },
  { value: 'nsx', label: 'NSX' },
  { value: 'external_checkpoint', label: 'External Checkpoint' },
  { value: 'internal_checkpoint', label: 'Internal Checkpoint' },
]

const ILLUMIO_STATUS_OPTIONS = [
  { value: '', label: 'All statuses' },
  { value: 'fully_enforced', label: 'Fully Enforced' },
  { value: 'partially_enforced', label: 'Partially Enforced' },
  { value: 'not_enforced', label: 'Not Enforced' },
]

const PAGE_SIZE_OPTIONS = [25, 50, 100]

function App() {
  const [applications, setApplications] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(50)

  const [searchInput, setSearchInput] = useState('')
  const [environment, setEnvironment] = useState('')
  const [firewall, setFirewall] = useState('')
  const [illumioStatus, setIllumioStatus] = useState('')

  const debouncedSearch = useDebouncedValue(searchInput, 300)

  useEffect(() => {
    setPage(1)
  }, [debouncedSearch, environment, firewall, illumioStatus])

  useEffect(() => {
    async function fetchApplications() {
      try {
        setLoading(true)
        setError(null)
        const params = new URLSearchParams()
        if (debouncedSearch?.trim()) params.set('search', debouncedSearch.trim())
        if (environment?.trim()) params.set('environment', environment.trim())
        if (firewall?.trim()) params.set('firewall', firewall.trim())
        if (illumioStatus?.trim()) params.set('illumio_status', illumioStatus.trim())
        params.set('page', String(page))
        params.set('limit', String(limit))

        const url = `/api/applications?${params.toString()}`
        const res = await fetch(url, {
          headers: {
            'X-AD-Groups': '',
          },
        })
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        setApplications(data.applications || [])
        setTotal(data.total ?? 0)
      } catch (err) {
        setError(err.message)
        setApplications([])
        setTotal(0)
      } finally {
        setLoading(false)
      }
    }
    fetchApplications()
  }, [debouncedSearch, environment, firewall, illumioStatus, page, limit])

  const totalPages = Math.max(1, Math.ceil(total / limit))
  const startItem = total === 0 ? 0 : (page - 1) * limit + 1
  const endItem = Math.min(page * limit, total)

  return (
    <div className="app">
      <header className="app-header">
        <h1>Frodo</h1>
        <p className="app-subtitle">Firewall Operations & Definition Orchestration</p>
      </header>

      <main className="app-main">
        <div className="app-toolbar">
          <input
            type="search"
            className="app-search"
            placeholder="Search applications…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          <select
            className="app-filter"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
            aria-label="Filter by environment"
          >
            {ENVIRONMENT_OPTIONS.map((opt) => (
              <option key={opt.value || 'all'} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          <select
            className="app-filter"
            value={firewall}
            onChange={(e) => setFirewall(e.target.value)}
            aria-label="Filter by firewall"
          >
            {FIREWALL_OPTIONS.map((opt) => (
              <option key={opt.value || 'all'} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          <select
            className="app-filter"
            value={illumioStatus}
            onChange={(e) => setIllumioStatus(e.target.value)}
            aria-label="Filter by Illumio status"
          >
            {ILLUMIO_STATUS_OPTIONS.map((opt) => (
              <option key={opt.value || 'all'} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          <div className="app-pagination-controls">
            <span className="app-pagination-info">
              Showing {startItem}–{endItem} of {total}
            </span>
            <select
              className="app-filter app-page-size"
              value={limit}
              onChange={(e) => {
                setLimit(Number(e.target.value))
                setPage(1)
              }}
              aria-label="Page size"
            >
              {PAGE_SIZE_OPTIONS.map((n) => (
                <option key={n} value={n}>
                  {n} per page
                </option>
              ))}
            </select>
            <div className="app-pagination-buttons">
              <button
                type="button"
                className="app-pagination-btn"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </button>
              <span className="app-pagination-page">
                Page {page} of {totalPages}
              </span>
              <button
                type="button"
                className="app-pagination-btn"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next
              </button>
            </div>
          </div>
        </div>

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
