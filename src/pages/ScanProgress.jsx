import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Check, Loader2 } from 'lucide-react'
import { Card, Button } from '../components/common/ui'
import { api } from '../services/api'
const stages = ['Reading dependency file', 'Extracting dependencies', 'Building component inventory', 'Checking vulnerabilities', 'Building dependency graph', 'Running risk analysis', 'Generating recommendations', 'Storing results']
export default function ScanProgress() {
  const [st, setSt] = useState({ status: 'QUEUED', stage: 0 }), [err, setErr] = useState(null), nav = useNavigate(), { id } = useParams()
  const done = st.status === 'COMPLETED', failed = st.status === 'FAILED'
  useEffect(() => { if (done || failed || err) return; const t = setTimeout(() => api.status(id).then(setSt).catch(e => setErr(e.message)), 700); return () => clearTimeout(t) }, [st, err])
  const step = done ? stages.length : st.stage
  return <div className="mx-auto max-w-xl pt-6"><Card className="hover:bg-card">
    <h1 className="text-xl font-bold">{done ? 'Analysis Complete' : failed ? 'Scan Failed' : 'Scanning dependency file...'}</h1>
    {(err || st.note) && <p className="mt-2 text-sm text-high">{err || st.note}</p>}
    <div className="my-5 h-2 overflow-hidden rounded-full bg-line"><div className="h-full rounded-full bg-gold transition-all duration-700" style={{ width: `${(step / stages.length) * 100}%` }} /></div>
    <ul className="space-y-3 text-sm">{stages.map((s, i) => <li key={s} className={`flex items-center gap-3 ${i > step ? 'text-mute/60' : i === step ? 'text-gold' : 'text-ink'}`}>{i < step ? <Check size={16} className="text-low" /> : i === step && !failed ? <Loader2 size={16} className="animate-spin" /> : <span className="w-4" />}{s}</li>)}</ul>
    {done && <Button className="mt-6 w-full" onClick={() => nav(`/scans/${id}`)}>View Scan Results</Button>}
    {failed && <Button className="mt-6 w-full" onClick={() => nav('/projects')}>Back to Projects</Button>}</Card></div>
}
