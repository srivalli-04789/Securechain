import { Link, useParams } from 'react-router-dom'
import { Card } from '../components/common/ui'
import useApi from '../hooks/useApi'
import { api } from '../services/api'
export function Overview() { const { id } = useParams(), { data: s } = useApi(() => api.scan(id), [id]), { data: a } = useApi(() => api.analysis(id), [id])
  return <div className="space-y-4"><Card className="hover:bg-card"><h2 className="text-lg font-bold">Scan overview</h2>
    <p className="mt-2 text-sm">{s ? s.counts_text : 'Loading scan results...'}</p>
    {a?.reasons?.length > 0 && <ul className="mt-3 space-y-1 text-sm">{a.reasons.map(r => <li key={r}>• {r}</li>)}</ul>}
    <p className="mt-3 text-xs text-mute">Everything in these tabs comes from your single uploaded requirements.txt and the vulnerability data returned by OSV for this scan.</p></Card>
    <Card className="hover:bg-card"><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{[['sbom', 'SBOM / Component Inventory', 'Packages and versions'], ['vulnerabilities', 'Vulnerabilities', 'Known advisories'], ['graph', 'Direct Dependency Graph', 'Direct dependencies only'], ['ai-risk', 'AI/ML Risk Analysis', 'Risk score and factors'], ['threats', 'Threat Intelligence', 'Advisories from OSV'], ['recommendations', 'Recommendations', 'What to fix first'], ['report', 'Report', 'Download PDF']].map(([p, t, d]) => <Link key={p} to={`/scans/${id}/${p}`} className="rounded-xl border border-line p-4 transition hover:bg-cardh"><b className="text-gold">{t}</b><p className="text-sm text-mute">{d}</p></Link>)}</div></Card></div> }
