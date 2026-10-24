import { NavLink, Outlet, useNavigate, useParams } from 'react-router-dom'
import { Button, Card, ErrorBox, Loading, PageHeader } from '../components/common/ui'
import DeleteControl from '../components/common/DeleteControl'
import { api } from '../services/api'
import useApi from '../hooks/useApi'
const tabs = [['', 'Overview'], ['sbom', 'SBOM / Component Inventory'], ['vulnerabilities', 'Vulnerabilities'], ['graph', 'Direct Dependency Graph'], ['ai-risk', 'AI/ML Risk Analysis'], ['threats', 'Threat Intelligence'], ['recommendations', 'Recommendations'], ['report', 'Report']]
const lc = { Critical: 'text-crit', High: 'text-high', Medium: 'text-med', Low: 'text-low' }
export default function ScanResults() {
  const { id } = useParams(), nav = useNavigate(), { data: s, loading, error } = useApi(() => api.scan(id), [id])
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />
  if (!s) return <Card className="py-10 text-center text-mute">No scan data available.</Card>
  const done = s.status === 'COMPLETED', del = <DeleteControl kind="scan" id={s.id} lastScan={s.project_scan_count === 1} label="Delete Scan" onDeleted={() => nav('/dashboard')} />
  const head = <PageHeader title="Scan Results" subtitle={`Project: ${s.project} · File: ${s.file} · Scanned: ${s.date} · Status: ${s.status}`} action={<div className="flex gap-2">{done && <NavLink to={`/scans/${id}/report`}><Button>Generate Report</Button></NavLink>}{del}</div>} />
  if (!done) return <>{head}<Card className="py-10 text-center"><p className={s.status === 'FAILED' ? 'text-crit' : 'text-mute'}>{s.status === 'FAILED' ? (s.note || 'This scan failed.') : 'This scan is still running.'}</p>
    {s.status !== 'FAILED' && <Button className="mt-4" onClick={() => nav(`/scans/${id}/progress`)}>View Progress</Button>}</Card></>
  const stat = [['Dependencies', s.deps], ['Unique vulnerabilities', s.vulns], ['Critical', s.critical, 'text-crit'], ['High', s.high, 'text-high'], ['Medium', s.medium, 'text-med'], ['Low', s.low, 'text-low']]
  return <>{head}
    {s.note && <p className="mb-4 rounded-xl border border-high/40 bg-high/10 px-4 py-3 text-sm text-high">{s.note}</p>}
    <div className="grid gap-4 lg:grid-cols-4"><Card><p className="text-sm text-mute">Overall Risk</p><p className="mt-2 text-4xl font-extrabold">{s.score} <span className="text-lg text-mute">/ 100</span></p><p className={`mt-1 text-sm font-bold tracking-wide ${lc[s.level] || ''}`}>{s.level.toUpperCase()} RISK{s.incomplete ? ' (incomplete data)' : ''}</p></Card>
      <div className="grid grid-cols-3 gap-4 lg:col-span-3">{stat.map(([l, v, c]) => <Card key={l} className="p-4"><p className="text-xs text-mute">{l}</p><p className={`mt-1 text-2xl font-bold ${c || ''}`}>{v}</p></Card>)}</div></div>
    <p className="mt-3 text-xs text-mute">{s.counts_text}{s.unknown ? ` ${s.unknown} of the unique vulnerabilities have no severity rating from the source and are not in the counts above.` : ''}</p>
    <nav className="mt-6 flex gap-1 overflow-x-auto border-b border-line">{tabs.map(([p, l]) => <NavLink key={l} to={`/scans/${id}/${p}`} end className={({ isActive }) => `whitespace-nowrap border-b-2 px-4 py-2.5 text-sm transition ${isActive ? 'border-gold text-gold' : 'border-transparent text-mute hover:text-ink'}`}>{l}</NavLink>)}</nav>
    <div className="mt-6"><Outlet /></div></>
}
