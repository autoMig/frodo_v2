import { useState, useEffect } from 'react'
import { Link, useParams } from 'react-router-dom'
import OverviewTab from './OverviewTab'
import IllumioTab from './IllumioTab'
import NSXPlaceholder from './NSXPlaceholder'
import CheckpointPlaceholder from './CheckpointPlaceholder'
import './ApplicationDetails.css'

const FIREWALL_KEYS = {
  illumio: 'illumio',
  nsx: 'nsx',
  external_checkpoint: 'external_checkpoint',
  internal_checkpoint: 'internal_checkpoint',
}

export default function ApplicationDetails() {
  const { app, env } = useParams()
  const [details, setDetails] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => {
    async function fetchDetails() {
      if (!app || !env) return
      try {
        setLoading(true)
        setError(null)
        const res = await fetch(
          `/api/applications/${encodeURIComponent(app)}/${encodeURIComponent(env)}`,
          { headers: { 'X-AD-Groups': '' } }
        )
        if (!res.ok) throw new Error(res.status === 404 ? 'Application not found' : `HTTP ${res.status}`)
        const data = await res.json()
        setDetails(data)
      } catch (err) {
        setError(err.message)
        setDetails(null)
      } finally {
        setLoading(false)
      }
    }
    fetchDetails()
  }, [app, env])

  if (loading) {
    return (
      <div className="app-details">
        <div className="app-loading">Loading application details…</div>
      </div>
    )
  }

  if (error || !details) {
    return (
      <div className="app-details">
        <div className="app-error">
          {error || 'Application not found'}
          <br />
          <Link to="/" className="app-details-back">← Back to applications</Link>
        </div>
      </div>
    )
  }

  const hasIllumio = details.firewalls?.includes(FIREWALL_KEYS.illumio)
  const hasNSX = details.firewalls?.includes(FIREWALL_KEYS.nsx)
  const hasCheckpoint = details.firewalls?.includes(FIREWALL_KEYS.external_checkpoint) ||
    details.firewalls?.includes(FIREWALL_KEYS.internal_checkpoint)

  const tabs = [
    { id: 'overview', label: 'Overview' },
    ...(hasIllumio ? [{ id: 'illumio', label: 'Illumio' }] : []),
    ...(hasNSX ? [{ id: 'nsx', label: 'NSX' }] : []),
    ...(hasCheckpoint ? [{ id: 'checkpoint', label: 'Checkpoint' }] : []),
  ]

  return (
    <div className="app-details">
      <header className="app-details-header">
        <Link to="/" className="app-details-back">← Back to applications</Link>
        <h1 className="app-details-title">
          {details.business_application_name?.toUpperCase()} | {details.environment?.toUpperCase()}
        </h1>
      </header>

      <nav className="app-details-tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`app-details-tab ${activeTab === tab.id ? 'app-details-tab--active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="app-details-content">
        {activeTab === 'overview' && <OverviewTab details={details} />}
        {activeTab === 'illumio' && <IllumioTab app={details.business_application_name} env={details.environment} />}
        {activeTab === 'nsx' && <NSXPlaceholder />}
        {activeTab === 'checkpoint' && <CheckpointPlaceholder />}
      </div>
    </div>
  )
}
