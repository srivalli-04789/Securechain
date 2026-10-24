import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { Card, Button, SeverityBadge, useToast, Loading, ErrorBox } from '../components/common/ui'
import { Table } from './DataPages'
import { api } from '../services/api'
import useApi from '../hooks/useApi'
const H = ({ t, sub }) => <div className="mb-4"><h2 className="text-xl font-bold">{t}</h2><p className="text-sm text-mute">{sub}</p></div>
function Live({ fn, empty, children }) {
  const { id } = useParams(), { data, loading, error } = useApi(() => fn(id), [id])
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />
  if (!data) return <Card className="py-10 text-center text-mute">No scan data available.</Card>
  if (Array.isArray(data) && !data.length) return <Card className="py-10 text-center text-mute">{empty}</Card>
  return children(data)
}
export const ScanSBOM = () => <><H t="SBOM / Component Inventory" sub="Packages and versions parsed from your requirements.txt. This is a component inventory, not a formal CycloneDX or SPDX document. Licenses are not available from this file." />
  <Live fn={api.sbom} empty="No components found.">{d => <Table rows={d} cols={[['Component', 'name'], ['Version', 'version'], ['Constraint', 'constraint'], ['Ecosystem', 'eco'], ['Type', 'type'], ['License', 'license'], ['Highest severity', 'risk', 1]]} />}</Live></>
export const ScanVulns = () => <><H t="Vulnerability Findings" sub="Unique vulnerabilities from OSV. Advisory identifiers (GHSA, PYSEC, CVE) that describe the same issue are merged into one row; the other identifiers are listed under Aliases." />
  <Live fn={api.vulns} empty="No vulnerabilities found.">{d => <Table rows={d} cols={[['Package', 'package'], ['Version', 'version'], ['Vulnerability', 'vuln'], ['Aliases', 'aliases'], ['Severity', 'severity', 1], ['CVSS', 'cvss'], ['Affected', 'affected'], ['Fixed', 'fixed'], ['Summary', 'summary']]} />}</Live></>
export const Recs = () => <><H t="Recommendations" sub="Generated from this scan's OSV findings and dependency pinning only." />
  <Live fn={api.recs} empty="No recommendations. No fixable findings were detected.">{d => <div className="space-y-3">{d.map(r => <Card key={r.text} className="flex items-center gap-4"><SeverityBadge level={r.level} /><p className="text-sm">{r.text}</p></Card>)}</div>}</Live></>
const lc = { Critical: 'text-crit', High: 'text-high', Medium: 'text-med', Low: 'text-low' }
export const AIRisk = () => <><H t="AI/ML Risk Analysis" sub="A transparent, rules-based analysis of this scan's real findings. No machine-learning model is running." />
  <Live fn={api.analysis}>{a => <div className="grid gap-4 lg:grid-cols-2"><Card className="hover:bg-card"><p className="text-sm text-mute">Overall Risk Score</p><p className="mt-1 text-4xl font-extrabold">{a.score} / 100</p><p className={`text-sm font-bold ${lc[a.level.charAt(0) + a.level.slice(1).toLowerCase()] || ''}`}>{a.level}{a.complete === false ? ' (incomplete data)' : ''}</p>
    <h3 className="mb-2 mt-5 text-sm font-semibold">Factors used by the risk engine</h3>
    <div className="space-y-3">{a.factors.map(f => <div key={f.n}><div className="flex justify-between text-sm"><span>{f.n}</span><span className="text-mute">{f.v}/100</span></div><div className="mt-1 h-2 rounded-full bg-line"><div className="h-2 rounded-full bg-gold" style={{ width: `${f.v}%` }} /></div>{f.detail && <p className="mt-0.5 text-xs text-mute">{f.detail}</p>}</div>)}</div>
    {a.formula && <p className="mt-4 text-xs text-mute">{a.formula}</p>}{a.levels_note && <p className="mt-1 text-xs text-mute">{a.levels_note}</p>}</Card>
    <div className="space-y-4"><Card className="hover:bg-card"><h3 className="mb-3 font-semibold">Why is this risky?</h3><ul className="space-y-2 text-sm">{a.reasons.map(r => <li key={r}>• {r}</li>)}</ul>
      {a.counts && <div className="mt-4 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">{[['Critical', a.counts.critical, 'text-crit'], ['High', a.counts.high, 'text-high'], ['Vulnerable deps', `${a.counts.vulnerable_pct}%`], ['Unpinned deps', a.counts.unpinned]].map(([l, v, c]) => <div key={l}><p className="text-xs text-mute">{l}</p><p className={`text-xl font-bold ${c || ''}`}>{v}</p></div>)}</div>}
      <p className="mt-4 text-xs text-mute">{a.transitive_note}</p></Card>
      <Card className="border-teal/30 hover:bg-card"><h3 className="mb-1 text-sm font-semibold text-teal">Machine-learning analysis</h3><p className="text-sm text-mute">{a.ml.note}</p></Card></div></div>}</Live></>
const rcol = { Critical: '#E86A6A', High: '#E6A85C', Medium: '#D6B878', Low: '#69C49A', 'None found': '#7DD3C7', Unknown: '#9FB8B2', 'Not checked': '#5C726D' }
export function GraphTab() {
  const { id } = useParams(), { data: g, loading, error } = useApi(() => api.graph(id), [id]), [sel, setSel] = useState(null)
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />
  const deps = g?.nodes.slice(1) || []; if (!deps.length) return <Card className="py-10 text-center text-mute">No scan data available.</Card>
  const pos = { root: [300, 40] }; deps.forEach((n, i) => { pos[n.id] = [60 + (i % 5) * 120, 130 + Math.floor(i / 5) * 90] })
  const cur = sel || g.nodes[0], h = 130 + Math.ceil(deps.length / 5) * 90
  return <><H t="Direct Dependency Graph" sub={`Your project and the ${deps.length} direct dependencies listed in requirements.txt. ${g.note}`} /><div className="grid gap-4 lg:grid-cols-3"><Card className="p-2 hover:bg-card lg:col-span-2"><svg viewBox={`0 0 600 ${h}`} className="w-full">{g.edges.map(([a, b]) => <line key={b} x1={pos[a][0]} y1={pos[a][1]} x2={pos[b][0]} y2={pos[b][1]} stroke="#1B5148" strokeWidth="2" />)}
    {g.nodes.map(n => <g key={n.id} onClick={() => setSel(n)} className="cursor-pointer"><circle cx={pos[n.id][0]} cy={pos[n.id][1]} r={cur.id === n.id ? 18 : 14} fill={n.id === 'root' ? '#D6B878' : rcol[n.risk] || '#7DD3C7'} stroke={cur.id === n.id ? '#F5F1E8' : '#062F2A'} strokeWidth="3" /><text x={pos[n.id][0]} y={pos[n.id][1] + 32} textAnchor="middle" fill="#9FB8B2" fontSize="11">{n.label.slice(0, 14)}</text></g>)}</svg><div className="flex flex-wrap gap-x-4 gap-y-1 px-3 pb-2 text-xs text-mute">{['Critical', 'High', 'Medium', 'Low', 'Unknown', 'None found', 'Not checked'].map(k => <span key={k} className="flex items-center gap-1"><i className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: rcol[k] }} />{k}</span>)}</div></Card>
    <Card><h3 className="font-semibold">{cur.label}</h3><dl className="mt-3 space-y-2 text-sm">{[['Version', cur.version || '—'], ['Type', cur.type], ['Risk', cur.risk], ['Vulnerabilities', cur.vulns], ['Dependencies', cur.id === 'root' ? cur.deps.join(', ') : 'Not available'], ['Dependents', cur.by.join(', ') || 'None']].map(([k, v]) => <div key={k} className="flex justify-between gap-3"><dt className="text-mute">{k}</dt><dd className="text-right">{v}</dd></div>)}</dl></Card></div></>
}
export const Threats = () => <><H t="Threat Intelligence" sub="Advisories retrieved from OSV for the dependencies in this scan, with severity, publication date and fixed version when OSV provides them." />
  <Live fn={api.threats} empty="No matching threat intelligence found.">{d => <Table rows={d} cols={[['Package', 'package'], ['Vulnerability', 'vuln'], ['Aliases', 'aliases'], ['Severity', 'severity', 1], ['Fixed in', 'fixed'], ['Published', 'published'], ['Modified', 'modified'], ['Summary', 'summary']]} />}</Live></>
export function ReportTab() {
  const { id } = useParams(), toast = useToast(), [busy, setBusy] = useState(false), { data: s } = useApi(() => api.scan(id), [id])
  const gen = async () => { setBusy(true); try { const b = await api.reportPdf(id), a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = `securechain-report-${id}.pdf`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); toast('Report generated successfully.') } catch (e) { toast(e.message) } setBusy(false) }
  return <><H t="SecureChain Security Report" sub="A PDF built from this scan's stored results." /><Card className="hover:bg-card"><p className="text-sm text-mute">{s ? `${s.project} · ${s.file} · ${s.date} · risk ${s.score}/100 (${s.level})` : 'Loading…'}</p><Button className="mt-4" disabled={busy || !s} onClick={gen}>{busy ? 'Generating report…' : 'Generate PDF Report'}</Button></Card></>
}
