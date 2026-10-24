import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, FolderGit2, Package, ShieldAlert, Flame } from 'lucide-react'
import { Card, Button, PageHeader, StatCard, SeverityBadge, useToast, Loading, ErrorBox } from '../components/common/ui'
import DeleteControl from '../components/common/DeleteControl'
import useApi from '../hooks/useApi'
import { api } from '../services/api'
export function Table({ cols, rows }) {
  const [q, setQ] = useState(''); const shown = rows.filter(r => JSON.stringify(r).toLowerCase().includes(q.toLowerCase()))
  return <Card className="hover:bg-card">
    <div className="mb-4 flex max-w-sm items-center gap-2 rounded-xl border border-line bg-bg2 px-3 py-2"><Search size={16} className="text-mute" /><input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter…" className="w-full bg-transparent text-sm outline-none" /></div>
    <div className="overflow-x-auto"><table className="w-full min-w-[640px] text-left text-sm"><thead><tr className="border-b border-line text-xs uppercase text-mute">{cols.map(c => <th key={c[0]} className="px-3 py-2 font-medium">{c[0]}</th>)}</tr></thead>
      <tbody>{shown.map((r, i) => <tr key={i} className="border-b border-line/50 hover:bg-cardh">{cols.map(c => <td key={c[0]} className="px-3 py-3">{c[2] ? <SeverityBadge level={r[c[1]]} /> : r[c[1]]}</td>)}</tr>)}{!shown.length && <tr><td colSpan={cols.length} className="px-3 py-10 text-center text-mute">No results.</td></tr>}</tbody></table></div>
  </Card>
}
export function Projects() {
  const nav = useNavigate(), toast = useToast(), { data, loading, error, reload } = useApi(api.projects, [])
  const rescan = async p => { try { const r = await api.rescan(p.id); nav(`/scans/${r.id}/progress`) } catch (e) { toast(e.message) } }
  return <><PageHeader title="Projects" subtitle="Manage scanned software projects." action={<Button onClick={() => nav('/scans/new')}>+ New Scan</Button>} />
    {loading ? <Loading text="Loading projects..." /> : error ? <ErrorBox error={error} text="Unable to load projects. Please try again." /> : !data.length ? <Card className="py-12 text-center text-mute">No projects yet. Click + New Scan to analyze your first project.</Card> :
    <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">{data.map(p => { const l = p.latest; return <Card key={p.id}><div className="flex items-start justify-between"><h3 className="font-semibold">{p.name}</h3>{l && <SeverityBadge level={l.risk || l.status} />}</div><p className="mt-1 text-sm text-mute">{p.description || 'No description'}</p>
      <div className="my-4 grid grid-cols-3 gap-2 text-sm"><div><p className="text-mute">Deps</p><b>{l ? l.deps : '—'}</b></div><div><p className="text-mute">Unique vulns</p><b>{l ? l.vulns : '—'}</b></div><div><p className="text-mute">Last scan</p><b>{l ? l.date : '—'}</b></div></div>
      <div className="flex gap-2"><Button onClick={() => nav(`/scans/${l.id}`)} disabled={!l} className="flex-1">View Results</Button><Button variant="ghost" onClick={() => rescan(p)} className="flex-1">Rescan</Button></div>
      <details className="mt-4 text-sm"><summary className="cursor-pointer text-mute hover:text-gold">Scan history ({p.history.length})</summary>
        <div className="mt-2 space-y-1">{p.history.map(h => <div key={h.id} className="flex items-center gap-2"><button onClick={() => nav(`/scans/${h.id}`)} className="grid flex-1 grid-cols-2 items-center gap-1 rounded-lg border border-line px-3 py-2 text-left text-xs transition hover:bg-cardh"><span>{h.date}</span><span className="text-mute">{h.status === 'COMPLETED' ? `${h.vulns} unique vulns · risk ${h.score}/100` : h.status}</span></button><DeleteControl kind="scan" id={h.id} lastScan={h.project_scan_count === 1} onDeleted={reload} className="!px-2 !py-1.5" /></div>)}</div></details>
      <div className="mt-3 flex justify-end"><DeleteControl kind="project" id={p.id} label="Delete Project" onDeleted={reload} className="!py-1.5 text-xs" /></div></Card> })}</div>}</>
}
