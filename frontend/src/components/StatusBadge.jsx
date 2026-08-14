export default function StatusBadge({ status }) {
  const s = (status || 'unknown').toLowerCase();
  let cls = 'badge-unknown';

  if (s === 'sent' || s === 'delivered') cls = 'badge-sent';
  else if (s === 'failed') cls = 'badge-failed';
  else if (s === 'bounced') cls = 'badge-bounced';
  else if (s === 'deferred') cls = 'badge-deferred';
  else if (s === 'timeout') cls = 'badge-timeout';
  else if (s === 'invalid') cls = 'badge-invalid';
  else if (s === 'spam') cls = 'badge-spam';
  else if (s === 'processing') cls = 'badge-processing';

  return <span className={`badge ${cls}`}>{status || 'unknown'}</span>;
}
