import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, Button, PageHeader, useToast } from '../components/common/ui'
import { PasswordField, rules } from './Auth'
import { api, token } from '../services/api'
import useApi from '../hooks/useApi'
export function Settings() {
  const { data: me } = useApi(api.me, []), toast = useToast(), nav = useNavigate(), [c, setC] = useState(''), [n, setN] = useState(''), [busy, setBusy] = useState(false), ok = rules.every(([, t]) => t(n))
  const change = async e => { e.preventDefault(); if (!ok || busy) return; setBusy(true); try { await api.changePassword({ current: c, new: n }); setC(''); setN(''); toast('Password changed successfully.') } catch (er) { toast(er.message) } setBusy(false) }
  return <><PageHeader title="Settings" subtitle="Manage your account and security." /><div className="grid gap-5 lg:grid-cols-2">
    <Card className="hover:bg-card"><h3 className="mb-3 font-semibold">Account Information</h3><p className="text-sm text-mute">Name</p><p>{me?.name || '…'}</p><p className="mt-3 text-sm text-mute">Email</p><p>{me?.email || '…'}</p>
      <Button variant="ghost" className="mt-5" onClick={() => { token.clear(); nav('/login') }}>Logout</Button></Card>
    <Card className="hover:bg-card"><h3 className="mb-3 font-semibold">Change Password</h3><form onSubmit={change} className="space-y-4"><PasswordField label="Current Password" value={c} onChange={e => setC(e.target.value)} /><PasswordField label="New Password" value={n} onChange={e => setN(e.target.value)} showRules /><Button type="submit" disabled={busy || !ok} className="disabled:opacity-50">{busy ? 'Saving…' : 'Change Password'}</Button></form></Card></div></>
}
export function Profile() {
  const { data: me } = useApi(api.me, []), { data: d } = useApi(api.dashboard, [])
  return <><PageHeader title="Profile" subtitle="Your SecureChain account." /><Card className="hover:bg-card"><div className="flex items-center gap-4"><div className="grid h-14 w-14 place-items-center rounded-full bg-gold text-xl font-bold text-bg">{(me?.name || '?')[0].toUpperCase()}</div><div><p className="font-semibold">{me?.name || '…'}</p><p className="text-sm text-mute">{me?.email}</p></div></div>
    <div className="mt-5 grid grid-cols-2 gap-4 text-sm"><div><p className="text-mute">Projects</p><b className="text-2xl">{d ? d.projects : '…'}</b></div><div><p className="text-mute">Scans</p><b className="text-2xl">{d ? d.total_scans : '…'}</b></div></div></Card></>
}
