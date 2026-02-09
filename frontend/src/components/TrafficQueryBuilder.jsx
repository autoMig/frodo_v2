import { useState } from 'react'
import './TrafficQueryBuilder.css'

const POLICY_DECISION_OPTIONS = [
  { value: 'allowed', label: 'Allowed' },
  { value: 'blocked', label: 'Blocked' },
  { value: 'potentially_blocked', label: 'Potentially Blocked' },
  { value: 'unknown', label: 'Unknown' },
]

function formatDate(d) {
  return d.toISOString().slice(0, 16)
}

function defaultStartDate() {
  const d = new Date()
  d.setDate(d.getDate() - 7)
  return formatDate(d)
}

function defaultEndDate() {
  return formatDate(new Date())
}

export default function TrafficQueryBuilder({ app, env }) {
  const [source, setSource] = useState(`${app}/${env}`)
  const [destination, setDestination] = useState('any')
  const [port, setPort] = useState('')
  const [protocol, setProtocol] = useState('tcp')
  const [startDate, setStartDate] = useState(defaultStartDate())
  const [endDate, setEndDate] = useState(defaultEndDate())
  const [policyDecisions, setPolicyDecisions] = useState(['allowed', 'blocked', 'potentially_blocked', 'unknown'])
  const [flows, setFlows] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  function togglePolicyDecision(value) {
    setPolicyDecisions((prev) =>
      prev.includes(value) ? prev.filter((p) => p !== value) : [...prev, value]
    )
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setFlows([])
    try {
      const body = {
        source: source.trim() || undefined,
        destination: destination.trim() === 'any' ? undefined : destination.trim() || undefined,
        port: port.trim() ? parseInt(port, 10) : undefined,
        protocol: protocol || undefined,
        start_date: new Date(startDate).toISOString(),
        end_date: new Date(endDate).toISOString(),
        policy_decisions: policyDecisions.length > 0 ? policyDecisions : undefined,
      }
      const res = await fetch(
        `/api/applications/${encodeURIComponent(app)}/${encodeURIComponent(env)}/illumio/traffic`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-AD-Groups': '',
          },
          body: JSON.stringify(body),
        }
      )
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        throw new Error(errData.detail || `HTTP ${res.status}`)
      }
      const data = await res.json()
      setFlows(data.flows || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="traffic-query-builder">
      <form className="traffic-query-form" onSubmit={handleSubmit}>
        <div className="traffic-query-row">
          <label>
            Source
            <input
              type="text"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              placeholder="app/env or IP"
            />
          </label>
          <label>
            Destination
            <input
              type="text"
              value={destination}
              onChange={(e) => setDestination(e.target.value)}
              placeholder="any"
            />
          </label>
        </div>
        <div className="traffic-query-row">
          <label>
            Port
            <input
              type="number"
              min="1"
              max="65535"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="optional"
            />
          </label>
          <label>
            Protocol
            <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </label>
        </div>
        <div className="traffic-query-row">
          <label>
            Start date
            <input
              type="datetime-local"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              required
            />
          </label>
          <label>
            End date
            <input
              type="datetime-local"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              required
            />
          </label>
        </div>
        <div className="traffic-query-row">
          <span className="traffic-query-label">Action (policy decision)</span>
          <div className="traffic-query-checkboxes">
            {POLICY_DECISION_OPTIONS.map((opt) => (
              <label key={opt.value} className="traffic-query-checkbox">
                <input
                  type="checkbox"
                  checked={policyDecisions.includes(opt.value)}
                  onChange={() => togglePolicyDecision(opt.value)}
                />
                {opt.label}
              </label>
            ))}
          </div>
        </div>
        <div className="traffic-query-actions">
          <button type="submit" disabled={loading}>
            {loading ? 'Running query…' : 'Submit query'}
          </button>
        </div>
      </form>

      {error && <div className="traffic-query-error">{error}</div>}

      {loading && (
        <p className="traffic-query-note">
          Async query may take 10–30+ seconds. Please wait…
        </p>
      )}

      {!loading && flows.length > 0 && (
        <div className="traffic-query-results">
          <h3>Results ({flows.length} flows)</h3>
          <table className="traffic-flows-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Destination</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Policy decision</th>
                <th>Connections</th>
              </tr>
            </thead>
            <tbody>
              {flows.map((f, i) => (
                <tr key={i}>
                  <td>{f.src}</td>
                  <td>{f.dst}</td>
                  <td>{f.port ?? '—'}</td>
                  <td>{f.protocol ?? '—'}</td>
                  <td>{f.policy_decision}</td>
                  <td>{f.num_connections}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!loading && flows.length === 0 && !error && (
        <p className="traffic-query-note">
          Fill in the query and click Submit to run traffic analysis.
        </p>
      )}
    </div>
  )
}
