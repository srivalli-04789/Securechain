const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
export const token = { get: () => localStorage.getItem('sc_token'), set: t => localStorage.setItem('sc_token', t), clear: () => localStorage.removeItem('sc_token') }
async function req(path, opts = {}) {
  const form = opts.body instanceof FormData
  const headers = { ...(opts.body && !form ? { 'Content-Type': 'application/json' } : {}), ...(token.get() ? { Authorization: `Bearer ${token.get()}` } : {}) }
  let r
  try { r = await fetch(BASE + '/api' + path, { ...opts, headers, body: opts.body && !form ? JSON.stringify(opts.body) : opts.body }) }
  catch { throw new Error('Cannot reach the SecureChain server. Is the backend running?') }
  if (r.status === 401 && token.get()) { token.clear(); location.href = '/login' }
  if (!r.ok) { let m = 'Request failed'; try { const d = (await r.json()).detail; m = typeof d === 'string' ? d : 'Please check your input.' } catch {} throw new Error(m) }
  return r.json()
}
const post = (p, body) => req(p, { method: 'POST', body })
const del = p => req(p, { method: 'DELETE' })
export const api = {
  register: b => post('/auth/register', b), login: b => post('/auth/login', b), me: () => req('/auth/me'),
  dashboard: () => req('/dashboard'), projects: () => req('/projects'), rescan: pid => post(`/projects/${pid}/rescan`),
  createScan: fd => post('/scans', fd), scan: id => req(`/scans/${id}`), status: id => req(`/scans/${id}/status`),
  sbom: id => req(`/scans/${id}/sbom`), graph: id => req(`/scans/${id}/graph`), threats: id => req(`/scans/${id}/threats`), riskHistory: () => req('/dashboard/risk-history'), severity: () => req('/dashboard/severity'),
  changePassword: b => post('/auth/change-password', b), deleteScan: id => del(`/scans/${id}`), deleteProject: id => del(`/projects/${id}`),
  reportPdf: async id => { const r = await fetch(`${BASE}/api/scans/${id}/report.pdf`, { headers: { Authorization: `Bearer ${token.get()}` } }); if (!r.ok) throw new Error('Could not generate the report.'); return r.blob() }, vulns: id => req(`/scans/${id}/vulnerabilities`), analysis: id => req(`/scans/${id}/analysis`), recs: id => req(`/scans/${id}/recommendations`),
}
