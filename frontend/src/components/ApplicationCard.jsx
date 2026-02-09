import { Link } from 'react-router-dom'
import './ApplicationCard.css';

const FIREWALL_LABELS = {
  illumio: 'Illumio',
  nsx: 'NSX',
  external_checkpoint: 'External Checkpoint',
  internal_checkpoint: 'Internal Checkpoint',
};

const ILLUMIO_STATUS_COLORS = {
  fully_enforced: '#22c55e',
  partially_enforced: '#f59e0b',
  not_enforced: '#ef4444',
};

const ILLUMIO_STATUS_LABELS = {
  fully_enforced: 'Fully Enforced',
  partially_enforced: 'Partially Enforced',
  not_enforced: 'Not Enforced',
};

function FirewallPill({ platform, illumioStatus }) {
  const label = FIREWALL_LABELS[platform] || platform;
  const isIllumio = platform === 'illumio';

  let className = 'pill';
  let style = {};

  if (isIllumio && illumioStatus) {
    className += ' pill--illumio';
    style.backgroundColor = ILLUMIO_STATUS_COLORS[illumioStatus] || '#6b7280';
    style.color = '#fff';
  } else {
    className += ' pill--default';
  }

  return (
    <span className={className} style={style} title={isIllumio && illumioStatus ? ILLUMIO_STATUS_LABELS[illumioStatus] : label}>
      {label}
      {isIllumio && illumioStatus && (
        <span className="pill__status"> ({ILLUMIO_STATUS_LABELS[illumioStatus]})</span>
      )}
    </span>
  );
}

export default function ApplicationCard({ application }) {
  const { business_application_name, environment, server_count, firewalls, illumio_enforcement_status } = application;
  const displayName = `${business_application_name.toUpperCase()} | ${environment.toUpperCase()}`;
  const to = `/applications/${encodeURIComponent(business_application_name)}/${encodeURIComponent(environment)}`;

  return (
    <Link to={to} className="application-card-link">
    <article className="application-card">
      <div className="application-card__header">
        <h2 className="application-card__title">{displayName}</h2>
        <span className="application-card__servers">{server_count} server{server_count !== 1 ? 's' : ''}</span>
      </div>
      <div className="application-card__firewalls">
        {firewalls.map((platform) => (
          <FirewallPill
            key={platform}
            platform={platform}
            illumioStatus={platform === 'illumio' ? illumio_enforcement_status : null}
          />
        ))}
      </div>
    </article>
    </Link>
  );
}
