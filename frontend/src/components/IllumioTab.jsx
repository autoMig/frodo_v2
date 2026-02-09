import { useState, useEffect } from 'react'
import TrafficQueryBuilder from './TrafficQueryBuilder'
import './IllumioTab.css'

const ILLUMIO_SUBTABS = [
  { id: 'workloads', label: 'Workloads' },
  { id: 'ruleset', label: 'Ruleset' },
  { id: 'traffic', label: 'Traffic' },
]

export default function IllumioTab({ app, env }) {
  const [activeSubTab, setActiveSubTab] = useState('workloads')
  const [workloads, setWorkloads] = useState([])
  const [workloadsLoading, setWorkloadsLoading] = useState(false)
  const [rulesets, setRulesets] = useState([])
  const [rulesetsLoading, setRulesetsLoading] = useState(false)

  useEffect(() => {
    if (activeSubTab === 'workloads') {
      setWorkloadsLoading(true)
      fetch(
        `/api/applications/${encodeURIComponent(app)}/${encodeURIComponent(env)}/illumio/workloads`,
        { headers: { 'X-AD-Groups': '' } }
      )
        .then((res) => (res.ok ? res.json() : Promise.reject(new Error(res.status))))
        .then((data) => setWorkloads(data.workloads || []))
        .catch(() => setWorkloads([]))
        .finally(() => setWorkloadsLoading(false))
    }
  }, [activeSubTab, app, env])

  useEffect(() => {
    if (activeSubTab === 'ruleset') {
      setRulesetsLoading(true)
      fetch(
        `/api/applications/${encodeURIComponent(app)}/${encodeURIComponent(env)}/illumio/rulesets`,
        { headers: { 'X-AD-Groups': '' } }
      )
        .then((res) => (res.ok ? res.json() : Promise.reject(new Error(res.status))))
        .then((data) => setRulesets(data.rulesets || []))
        .catch(() => setRulesets([]))
        .finally(() => setRulesetsLoading(false))
    }
  }, [activeSubTab, app, env])

  return (
    <div className="illumio-tab">
      <nav className="illumio-subtabs">
        {ILLUMIO_SUBTABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`illumio-subtab ${activeSubTab === tab.id ? 'illumio-subtab--active' : ''}`}
            onClick={() => setActiveSubTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="illumio-subtab-content">
        {activeSubTab === 'workloads' && (
          <div className="illumio-workloads">
            {workloadsLoading ? (
              <div className="app-loading">Loading workloads…</div>
            ) : (
              <table className="illumio-table">
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>Enforcement mode</th>
                    <th>App label</th>
                    <th>Env label</th>
                    <th>Loc label</th>
                  </tr>
                </thead>
                <tbody>
                  {workloads.length === 0 ? (
                    <tr>
                      <td colSpan={5}>No workloads found</td>
                    </tr>
                  ) : (
                    workloads.map((w) => (
                      <tr key={w.hostname}>
                        <td>{w.hostname}</td>
                        <td>{w.enforcement_mode || '—'}</td>
                        <td>{w.app_label || '—'}</td>
                        <td>{w.env_label || '—'}</td>
                        <td>{w.loc_label || '—'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeSubTab === 'ruleset' && (
          <div className="illumio-rulesets">
            {rulesetsLoading ? (
              <div className="app-loading">Loading rulesets…</div>
            ) : (
              <div className="illumio-rulesets-list">
                {rulesets.length === 0 ? (
                  <p>No rulesets found for this application.</p>
                ) : (
                  rulesets.map((rs) => (
                    <details key={rs.href} className="illumio-ruleset">
                      <summary>{rs.name}</summary>
                      <ul className="illumio-rules">
                        {rs.rules?.length === 0 ? (
                          <li>No rules</li>
                        ) : (
                          rs.rules?.map((r) => (
                            <li key={r.href}>
                              {r.description || r.href}
                            </li>
                          ))
                        )}
                      </ul>
                    </details>
                  ))
                )}
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'traffic' && (
          <TrafficQueryBuilder app={app} env={env} />
        )}
      </div>
    </div>
  )
}
