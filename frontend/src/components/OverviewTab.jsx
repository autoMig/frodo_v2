import './OverviewTab.css'

const FIREWALL_LABELS = {
  illumio: 'Illumio',
  nsx: 'NSX',
  external_checkpoint: 'External Checkpoint',
  internal_checkpoint: 'Internal Checkpoint',
}

const ILLUMIO_STATUS_COLORS = {
  fully_enforced: '#22c55e',
  partially_enforced: '#f59e0b',
  not_enforced: '#ef4444',
}

const ILLUMIO_STATUS_LABELS = {
  fully_enforced: 'Fully Enforced',
  partially_enforced: 'Partially Enforced',
  not_enforced: 'Not Enforced',
}

function FirewallPill({ platform, illumioStatus }) {
  const label = FIREWALL_LABELS[platform] || platform
  const isIllumio = platform === 'illumio'

  let className = 'pill'
  let style = {}

  if (isIllumio && illumioStatus) {
    className += ' pill--illumio'
    style.backgroundColor = ILLUMIO_STATUS_COLORS[illumioStatus] || '#6b7280'
    style.color = '#fff'
  } else {
    className += ' pill--default'
  }

  return (
    <span className={className} style={style} title={isIllumio && illumioStatus ? ILLUMIO_STATUS_LABELS[illumioStatus] : label}>
      {label}
      {isIllumio && illumioStatus && (
        <span className="pill__status"> ({ILLUMIO_STATUS_LABELS[illumioStatus]})</span>
      )}
    </span>
  )
}

export default function OverviewTab({ details }) {
  const { hosts = [], firewalls = [], illumio_enforcement_status } = details

  return (
    <div className="overview-tab">
      <section className="overview-section">
        <h2 className="overview-section__title">Hosts</h2>
        <ul className="overview-hosts">
          {hosts.length === 0 ? (
            <li className="overview-hosts__empty">No hosts</li>
          ) : (
            hosts.map((host) => (
              <li key={host} className="overview-hosts__item">{host}</li>
            ))
          )}
        </ul>
      </section>

      <section className="overview-section">
        <h2 className="overview-section__title">Firewalls</h2>
        <div className="overview-firewalls">
          {firewalls.map((platform) => (
            <FirewallPill
              key={platform}
              platform={platform}
              illumioStatus={platform === 'illumio' ? illumio_enforcement_status : null}
            />
          ))}
          {firewalls.length === 0 && (
            <span className="overview-firewalls__empty">None</span>
          )}
        </div>
      </section>
    </div>
  )
}

