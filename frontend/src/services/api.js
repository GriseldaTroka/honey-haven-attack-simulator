const json = async (response) => {
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`)
  return payload
}

export const api = {
  bootstrap: () => fetch('/api/bootstrap').then(json),
  runs: () => fetch('/api/runs').then(json),
  run: (id) => fetch(`/api/runs/${id}`).then(json),
  start: (payload) => fetch('/api/runs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }).then(json),
  evaluations: () => fetch('/api/evaluations').then(json),
}
