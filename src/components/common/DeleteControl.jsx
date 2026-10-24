import { useState } from 'react'
import { Trash2 } from 'lucide-react'
import { Button, ConfirmDialog, useToast } from './ui'
import { api } from '../../services/api'
const TEXT = {
  scan: ['Delete this scan?', 'All vulnerability results, dependency data, analysis results and the associated scan data will be permanently deleted.'],
  project: ['Delete this project?', 'The project and all of its scans will be permanently deleted, including all vulnerability results, dependency data, analysis results and the associated scan data.'],
}
// Trash button + confirmation dialog. The backend verifies ownership; this component only asks and reports the real result/error.
export default function DeleteControl({ kind = 'scan', id, lastScan, onDeleted, label, className = '' }) {
  const [open, setOpen] = useState(false), [busy, setBusy] = useState(false), [err, setErr] = useState(null), toast = useToast(), [title, text] = TEXT[kind], name = kind === 'scan' ? 'Delete Scan' : 'Delete Project'
  const close = () => { setOpen(false); setErr(null) }
  const go = async () => { setBusy(true); setErr(null); try { const r = await (kind === 'scan' ? api.deleteScan(id) : api.deleteProject(id)); setOpen(false); toast(kind === 'scan' ? 'Scan deleted successfully.' : 'Project deleted successfully.'); onDeleted?.(r) } catch (e) { setErr(e.message) } setBusy(false) }
  return <>
    <Button variant="ghost" title={name} aria-label={name} onClick={() => setOpen(true)} className={`${label ? '' : 'px-2.5'} hover:!border-crit/50 hover:!text-crit ${className}`}><Trash2 size={16} />{label}</Button>
    {open && <ConfirmDialog title={title} text={text} note={kind === 'scan' && lastScan ? 'This is the only scan in its project, so the project will be removed as well.' : null} error={err} busy={busy} onCancel={close} onConfirm={go} />}</>
}
