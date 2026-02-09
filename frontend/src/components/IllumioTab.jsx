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
  const [rulesetData, setRulesetData] = useState({ application_rules: [], external_rules: [] })
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
        .then((data) =>
          setRulesetData({
            application_rules: data.application_rules || [],
            external_rules: data.external_rules || [],
          })
        )
        .catch(() => setRulesetData({ application_rules: [], external_rules: [] }))
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
              <div className="app-loading">Loading rules…</div>
            ) : (
              <div className="illumio-rulesets-list">
                {rulesetData.application_rules.length === 0 &&
                rulesetData.external_rules.length === 0 ? (
                  <p>No rules found for this application.</p>
                ) : (
                  <>
                    {rulesetData.application_rules.length > 0 && (
                      <section className="illumio-rules-section">
                        <h4>Application rules</h4>
                        <div className="illumio-rules-table-wrapper">
                          <table className="illumio-table illumio-rules-table">
                            <thead>
                              <tr>
                                <th>Ruleset Name</th>
                                <th>Rule Type</th>
                                <th>Source</th>
                                <th>Destination</th>
                                <th>Port/Protocol</th>
                                <th>Description</th>
                              </tr>
                            </thead>
                            <tbody>
                              {rulesetData.application_rules.map((r) => (
                                <tr key={r.href}>
                                  <td>{r.ruleset_name || '—'}</td>
                                  <td>
                                    <span className="illumio-rule-badge">
                                      {r.rule_type_display || (r.category === 'application_inbound' ? 'Inbound' : 'Internal')}
                                    </span>
                                  </td>
                                  <td>{r.source_labels?.length ? r.source_labels.join(', ') : '—'}</td>
                                  <td>{r.destination_labels?.length ? r.destination_labels.join(', ') : '—'}</td>
                                  <td>{r.ingress_services_summary || '—'}</td>
                                  <td>{r.description || '—'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </section>
                    )}
                    {rulesetData.external_rules.length > 0 && (
                      <section className="illumio-rules-section">
                        <h4>External rules</h4>
                        <div className="illumio-rules-table-wrapper">
                          <table className="illumio-table illumio-rules-table">
                            <thead>
                              <tr>
                                <th>Ruleset Name</th>
                                <th>Rule Type</th>
                                <th>Source</th>
                                <th>Destination</th>
                                <th>Port/Protocol</th>
                                <th>Description</th>
                              </tr>
                            </thead>
                            <tbody>
                              {rulesetData.external_rules.map((r) => (
                                <tr key={r.href}>
                                  <td>{r.ruleset_name || '—'}</td>
                                  <td>
                                    <span className="illumio-rule-badge">
                                      {r.rule_type_display || 'External'}
                                    </span>
                                  </td>
                                  <td>{r.source_labels?.length ? r.source_labels.join(', ') : '—'}</td>
                                  <td>{r.destination_labels?.length ? r.destination_labels.join(', ') : '—'}</td>
                                  <td>{r.ingress_services_summary || '—'}</td>
                                  <td>{r.description || '—'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </section>
                    )}
                  </>
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
