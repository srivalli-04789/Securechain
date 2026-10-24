import { useNavigate } from 'react-router-dom'
import { Plus, Radar, FolderGit2, Package, ShieldAlert, Flame } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { Button, Card, PageHeader, StatCard, SeverityBadge, ErrorBox } from '../components/common/ui'
import DeleteControl from '../components/common/DeleteControl'
import useApi from '../hooks/useApi'
import { api } from '../services/api'
const col = { Critical: '#E86A6A', High: '#E6A85C', Medium: '#D6B878', Low: '#69C49A', Unknown: '#9FB8B2' }
const tip = { contentStyle: { background: '#083A33', border: '1px solid #1B5148', borderRadius: 12, color: '#F5F1E8' } }
export default function Dashboard() {
  const nav = useNavigate(), { data: d, loading, error, reload: r1 } = useApi(api.dashboard, []), { data: hist, reload: r2 } = useApi(api.riskHistory, []), { data: sev, reload: r3 } = useApi(api.severity, []), reload = () => { r1(); r2(); r3() }
  const v = k => (d ? d[k] : '…'), pie = (sev || []).filter(x => x.v > 0)
  return <><PageHeader title="SecureChain" subtitle="AI-Driven Software Dependency Threat Detection" action={<Button onClick={() => nav('/scans/new')}><Plus size={16} />New Scan</Button>} /><p className="-mt-3 mb-5 text-lg">Welcome back</p>
    {error && <div className="mb-5"><ErrorBox error={error} text="Unable to load the dashboard. Please try again." /></div>}
    <div className="grid grid-cols-2 gap-4 xl:grid-cols-5"><StatCard label="Total Scans" value={v('total_scans')} icon={Radar} /><StatCard label="Projects" value={v('projects')} icon={FolderGit2} /><StatCard label="Dependencies" value={v('dependencies')} icon={Package} /><StatCard label="Unique Vulnerabilities" value={v('vulnerabilities')} icon={ShieldAlert} /><StatCard label="Critical Findings" value={v('critical')} icon={Flame} /></div>
    <p className="mt-2 text-xs text-mute">Dependency, vulnerability and critical counts, and the severity chart, reflect the latest completed scan of each project.</p>
    <Card className="mt-5 hover:bg-card"><h3 className="mb-3 font-semibold">Recent Scans</h3>{loading ? <p className="text-sm text-mute">Loading dashboard…</p> : !d?.recent.length ? <p className="text-sm text-mute">No scans yet. Click + New Scan to analyze your first project.</p> :
      <div className="space-y-2">{d.recent.map(x => <div key={x.id} className="flex items-center gap-2"><button onClick={() => nav(`/scans/${x.id}`)} className="grid flex-1 grid-cols-2 items-center gap-2 rounded-xl border border-line px-4 py-3 text-left text-sm transition hover:bg-cardh md:grid-cols-6"><b>{x.project}</b><span className="text-mute">{x.file}</span><span className="text-mute">{x.date}</span><span>{x.risk ? <SeverityBadge level={x.risk} /> : '—'}</span><span>{x.status === 'COMPLETED' ? `${x.vulns} unique vulnerabilities` : '—'}</span><span className={x.status === 'COMPLETED' ? 'text-low' : x.status === 'FAILED' ? 'text-crit' : 'text-high'}>{x.status}</span></button><DeleteControl kind="scan" id={x.id} lastScan={x.project_scan_count === 1} onDeleted={reload} /></div>)}</div>}</Card>
    <div className="mt-5 grid gap-5 lg:grid-cols-3">
      <Card className="lg:col-span-2"><h3 className="mb-3 font-semibold">Risk Overview</h3>{!hist?.length ? <p className="text-sm text-mute">No completed scans yet.</p> : <><div className="h-60"><ResponsiveContainer><LineChart data={hist}><XAxis dataKey="date" stroke="#9FB8B2" tickFormatter={t => t.slice(5, 10)} /><YAxis domain={[0, 100]} stroke="#9FB8B2" /><Tooltip {...tip} /><Line dataKey="score" name="Risk score" stroke="#D6B878" strokeWidth={2} dot={{ r: 5, fill: '#D6B878' }} /></LineChart></ResponsiveContainer></div>{hist.length < 2 && <p className="mt-2 text-xs text-mute">Risk history will appear as more scans are completed.</p>}</>}</Card>
      <Card><h3 className="mb-3 font-semibold">Vulnerability Severity</h3>{!pie.length ? <p className="text-sm text-mute">No vulnerabilities found.</p> : <div className="h-60"><ResponsiveContainer><PieChart><Pie data={pie} dataKey="v" nameKey="n" innerRadius={50} outerRadius={85} stroke="none">{pie.map(x => <Cell key={x.n} fill={col[x.n]} />)}</Pie><Tooltip {...tip} /></PieChart></ResponsiveContainer></div>}</Card>
    </div></>
}
