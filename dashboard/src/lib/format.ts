export function formatTimestamp(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

export function severityTone(severity: string) {
  switch (severity) {
    case 'critical':
      return 'tone-critical'
    case 'high':
      return 'tone-high'
    case 'medium':
      return 'tone-medium'
    case 'low':
      return 'tone-low'
    default:
      return 'tone-info'
  }
}
