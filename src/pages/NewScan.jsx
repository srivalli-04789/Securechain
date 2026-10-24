import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { UploadCloud, Check } from 'lucide-react'
import { Card, Button, PageHeader, useToast } from '../components/common/ui'
import { api } from '../services/api'
const types = { 'requirements.txt': 'Python Dependency File' }
export default function NewScan() {
  const nav = useNavigate(), toast = useToast(), ref = useRef(), [file, setFile] = useState(null), [name, setName] = useState(''), [desc, setDesc] = useState(''), [drag, setDrag] = useState(false)
  const pick = f => { if (!f) return; if (!types[f.name]) return toast('Unsupported file. Only requirements.txt is supported.'); setFile(f) }
  const busy = useRef(false)
  const start = async () => { if (busy.current) return; if (!file) return toast('Upload a dependency file first.'); if (!name.trim()) return toast('Enter a project name.'); const fd = new FormData(); fd.append('project_name', name.trim()); fd.append('description', desc); fd.append('dependency_file', file); busy.current = true; try { const r = await api.createScan(fd); nav(`/scans/${r.id}/progress`) } catch (e) { busy.current = false; toast(e.message) } }
  const field = 'mt-1 w-full rounded-xl border border-line bg-bg2 px-3 py-2.5 text-sm outline-none focus:border-gold'
  return <><PageHeader title="Run a New Scan" subtitle="Upload your project's requirements.txt to analyze its Python dependencies." />
    <div className="mx-auto max-w-2xl space-y-5">
      <p className="rounded-xl border border-gold/30 bg-gold/10 px-4 py-3 text-sm text-gold">Upload one requirements.txt — SecureChain analyzes it and builds the component inventory, vulnerability findings, direct dependency graph, risk analysis and recommendations. The file is parsed, never executed.</p>
      <Card className="hover:bg-card">
        {!file ? <div onDragOver={e => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={e => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files[0]) }}
          className={`rounded-2xl border-2 border-dashed p-10 text-center transition ${drag ? 'border-gold bg-cardh' : 'border-line'}`}>
          <UploadCloud className="mx-auto text-gold" size={40} /><h3 className="mt-3 font-semibold">Upload requirements.txt</h3><p className="mt-1 text-sm text-mute">Drag & drop your file here, or</p>
          <Button className="mt-3" onClick={() => ref.current.click()}>Browse Files</Button><input ref={ref} type="file" className="hidden" accept=".txt" onChange={e => pick(e.target.files[0])} />
          <p className="mt-4 text-xs text-mute">Supported file: requirements.txt</p></div>
        : <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="flex items-center gap-2 font-semibold text-low"><Check size={18} />{file.name}</p><p className="mt-1 text-sm text-mute">{types[file.name]} · {Math.max(1, Math.round(file.size / 1024))} KB</p></div><Button variant="ghost" onClick={() => setFile(null)}>Remove File</Button></div>}
      </Card>
      <Card className="space-y-4 hover:bg-card">
        <label className="block text-sm text-mute">Project Name<input value={name} onChange={e => setName(e.target.value)} placeholder="Enter project name" className={field} /></label>
        <label className="block text-sm text-mute">Project Description (optional)<textarea value={desc} onChange={e => setDesc(e.target.value)} rows={3} placeholder="Enter description" className={field} /></label>
        <Button onClick={start} className="w-full">Start Scan</Button></Card></div></>
}
