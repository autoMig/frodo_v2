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
                        <ul className="illumio-rules">
                          {rulesetData.application_rules.map((r) => (
                            <li key={r.href} className="illumio-rule">
                              <span className="illumio-rule-badge">
                                {r.category === 'application_inbound'
                                  ? 'Inbound'
                                  : 'Intra-scope'}
                              </span>
                              {r.description || r.href}
                              {r.ingress_services_summary && (
                                <span className="illumio-rule-services">
                                  {' '}({r.ingress_services_summary})
                                </span>
                              )}
                              <div className="illumio-rule-labels">
                                Consumer: {r.consumer_labels?.length ? r.consumer_labels.join(', ') : '—'}
                                {' → '}Provider: {r.provider_labels?.length ? r.provider_labels.join(', ') : '—'}
                              </div>
                            </li>
                          ))}
                        </ul>
                      </section>
                    )}
                    {rulesetData.external_rules.length > 0 && (
                      <section className="illumio-rules-section">
                        <h4>External rules</h4>
                        <ul className="illumio-rules">
                          {rulesetData.external_rules.map((r) => (
                            <li key={r.href} className="illumio-rule">
                              {r.description || r.href}
                              {r.ingress_services_summary && (
                                <span className="illumio-rule-services">
                                  {' '}({r.ingress_services_summary})
                                </span>
                              )}
                              {r.ruleset_name && (
                                <span className="illumio-rule-ruleset"> — {r.ruleset_name}</span>
                              )}
                              <div className="illumio-rule-labels">
                                Consumer: {r.consumer_labels?.length ? r.consumer_labels.join(', ') : '—'}
                                {' → '}Provider: {r.provider_labels?.length ? r.provider_labels.join(', ') : '—'}
                              </div>
                            </li>
                          ))}
                        </ul>
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
