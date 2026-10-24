import { useState } from 'react'
import { NavLink, Link, Outlet, Navigate } from 'react-router-dom'
import { LayoutDashboard, FolderGit2, Boxes, ShieldAlert, Network, BrainCircuit, Radar, FileText, Settings, User, LogOut, Menu, Bell, Search, ShieldCheck, Plus } from 'lucide-react'
import { useToast } from '../components/common/ui'
import { token, api } from '../services/api'
import useApi from '../hooks/useApi'
const nav = [['/dashboard','Dashboard',LayoutDashboard],['/scans/new','New Scan',Plus],['/projects','Projects',FolderGit2],['/settings','Settings',Settings]]
export default function AppLayout() {
  const [open, setOpen] = useState(false); const toast = useToast()
  const { data: me } = useApi(api.me, [])
  if (!token.get()) return <Navigate to="/login" replace />
  const item = (to, label, Icon) => <NavLink key={to} to={to} onClick={() => setOpen(false)} className={({ isActive }) => `flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition ${isActive ? 'bg-gold/15 text-gold' : 'text-mute hover:bg-card hover:text-ink'}`}><Icon size={18} />{label}</NavLink>
  return <div className="min-h-screen">
    {open && <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={() => setOpen(false)} />}
    <aside className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-line bg-bg2 p-4 transition-transform lg:translate-x-0 ${open ? '' : '-translate-x-full'}`}>
      <Link to="/" className="mb-6 flex items-center gap-2 px-2 text-lg font-bold"><ShieldCheck className="text-gold" />SecureChain</Link>
      <nav className="flex-1 space-y-1">{nav.map(n => item(...n))}</nav>
      <div className="space-y-1 border-t border-line pt-3">{item('/profile','Profile',User)}<Link to="/login" onClick={() => token.clear()} className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-mute hover:bg-card hover:text-ink"><LogOut size={18} />Logout</Link></div>
    </aside>
    <div className="lg:pl-64">
      <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-line bg-bg/90 px-5 py-3 backdrop-blur">
        <button className="lg:hidden" onClick={() => setOpen(true)} aria-label="Menu"><Menu /></button>
        <div className="flex flex-1 items-center gap-2 rounded-xl border border-line bg-bg2 px-3 py-2 sm:max-w-md"><Search size={16} className="text-mute" /><input onKeyDown={e => e.key === 'Enter' && toast('Global search is not available yet.')} placeholder="Search packages, CVEs, projects…" className="w-full bg-transparent text-sm outline-none placeholder:text-mute" /></div>
        <button onClick={() => toast('No new notifications.')} className="ml-auto rounded-xl border border-line p-2 text-mute hover:text-gold"><Bell size={18} /></button>
        <Link to="/profile" className="grid h-9 w-9 place-items-center rounded-full bg-gold font-bold text-bg">{(me?.name || '?')[0].toUpperCase()}</Link>
      </header>
      <main className="p-5 lg:p-8"><Outlet /></main>
    </div>
  </div>
}
