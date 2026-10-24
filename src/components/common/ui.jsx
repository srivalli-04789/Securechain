import { createContext, useContext, useEffect, useState } from 'react'
const T = createContext(() => {})
export const useToast = () => useContext(T)
export function ToastProvider({ children }) {
  const [t, setT] = useState(null)
  const push = (m) => { setT(m); setTimeout(() => setT(null), 2600) }
  return <T.Provider value={push}>{children}{t && <div className="fixed bottom-5 right-5 z-50 rounded-xl border border-gold/40 bg-card px-4 py-3 text-sm shadow-xl">{t}</div>}</T.Provider>
}
export const Card = ({ className = '', children }) => <div className={`rounded-2xl border border-line bg-card p-5 shadow-lg shadow-black/20 transition-colors hover:bg-cardh ${className}`}>{children}</div>
export const Button = ({ variant = 'gold', className = '', ...p }) => <button {...p} className={`inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition ${variant === 'gold' ? 'bg-gold text-bg hover:brightness-110' : variant === 'danger' ? 'bg-crit text-bg hover:brightness-110' : 'border border-line text-ink hover:bg-cardh'} disabled:cursor-not-allowed disabled:opacity-50 ${className}`} />
export const PageHeader = ({ title, subtitle, action }) => <div className="mb-6 flex flex-wrap items-start justify-between gap-3"><div><h1 className="text-2xl font-bold">{title}</h1><p className="mt-1 text-sm text-mute">{subtitle}</p></div>{action}</div>
export const StatCard = ({ label, value, icon: Icon }) => <Card><div className="flex items-center justify-between"><p className="text-sm text-mute">{label}</p><Icon size={18} className="text-gold" /></div><p className="mt-3 text-3xl font-bold">{value}</p></Card>
const cls = { Critical:'text-crit bg-crit/10 border-crit/30', High:'text-high bg-high/10 border-high/30', Medium:'text-med bg-med/10 border-med/30', Low:'text-low bg-low/10 border-low/30', Unknown:'text-mute bg-mute/10 border-mute/30', 'Not checked':'text-mute bg-mute/10 border-mute/30' }
export const SeverityBadge = ({ level }) => <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${cls[level] || 'text-teal bg-teal/10 border-teal/30'}`}>{level}</span>
export const EmptyState = ({ title, text }) => <Card className="py-16 text-center"><h2 className="text-lg font-semibold">{title}</h2><p className="mx-auto mt-2 max-w-md text-sm text-mute">{text}</p></Card>
export const Loading = ({ text = 'Loading scan results...' }) => <p className="text-mute">{text}</p>
export const ErrorBox = ({ error, text = 'Unable to load scan results. Please try again.' }) => <Card><p className="text-crit">{text}</p>{error && <p className="mt-1 text-xs text-mute">{error}</p>}</Card>
export function ConfirmDialog({ title, text, note, error, busy, confirmLabel = 'Delete', onCancel, onConfirm }) {
  useEffect(() => { const k = e => e.key === 'Escape' && !busy && onCancel(); window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k) }, [busy])
  return <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-5" role="dialog" aria-modal="true" aria-labelledby="dlg-title" onClick={e => e.target === e.currentTarget && !busy && onCancel()}>
    <Card className="w-full max-w-md hover:bg-card"><h2 id="dlg-title" className="text-lg font-bold">{title}</h2><p className="mt-2 text-sm text-mute">{text}</p>{note && <p className="mt-2 text-sm text-high">{note}</p>}
      {error && <p role="alert" className="mt-3 rounded-xl border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-crit">{error}</p>}
      <div className="mt-5 flex justify-end gap-2"><Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button><Button variant="danger" onClick={onConfirm} disabled={busy}>{busy ? 'Deleting...' : confirmLabel}</Button></div></Card></div>
}
