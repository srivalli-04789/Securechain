import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ShieldCheck, Eye, EyeOff, Check, X } from 'lucide-react'
import { Button, Card, useToast } from '../components/common/ui'
import { api, token } from '../services/api'
export const rules = [['At least 8 characters', p => p.length >= 8], ['One uppercase letter', p => /[A-Z]/.test(p)], ['One lowercase letter', p => /[a-z]/.test(p)], ['One number', p => /\d/.test(p)], ['One special character', p => /[^A-Za-z0-9]/.test(p)]]
export const validEmail = e => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)
const box = 'mt-1 w-full rounded-xl border border-line bg-bg2 px-3 py-2.5 text-sm outline-none focus:border-gold'
export function PasswordField({ label, value, onChange, showRules }) {
  const [show, setShow] = useState(false)
  return <div><label className="text-sm text-mute">{label}</label><div className="relative"><input required aria-label={label} type={show ? 'text' : 'password'} value={value} onChange={onChange} className={box + ' pr-10'} />
    <button type="button" onClick={() => setShow(!show)} aria-label={show ? 'Hide password' : 'Show password'} className="absolute right-3 top-1/2 -translate-y-1/2 text-mute hover:text-gold">{show ? <EyeOff size={18} /> : <Eye size={18} />}</button></div>
    {showRules && <ul className="mt-2 space-y-1 text-xs"><li className="text-mute">Password must contain:</li>{rules.map(([t, f]) => <li key={t} className={`flex items-center gap-2 ${f(value) ? 'text-low' : 'text-mute'}`}>{f(value) ? <Check size={14} /> : <X size={14} />}{t}</li>)}</ul>}</div>
}
export default function Auth({ mode }) {
  const reg = mode === 'register', nav = useNavigate(), toast = useToast(), [f, setF] = useState({ name: '', email: '', password: '', confirm: '' }), [busy, setBusy] = useState(false), [touched, setTouched] = useState(false)
  const set = k => e => setF({ ...f, [k]: e.target.value }), emailBad = touched && !validEmail(f.email), ok = rules.every(([, t]) => t(f.password)), mismatch = reg && f.confirm && f.password !== f.confirm
  const submit = async e => {
    e.preventDefault(); setTouched(true); if (!validEmail(f.email) || busy) return
    if (reg && (!ok || f.password !== f.confirm)) return toast('Please meet all password requirements and confirm your password.')
    setBusy(true)
    try { if (reg) await api.register({ name: f.name, email: f.email, password: f.password }); const r = await api.login({ email: f.email, password: f.password }); token.set(r.access_token); nav('/dashboard') }
    catch (er) { toast(er.message); setBusy(false) }
  }
  return <div className="grid min-h-screen place-items-center p-5"><Card className="w-full max-w-md hover:bg-card"><div className="mb-6"><div className="flex items-center gap-2 text-lg font-bold"><ShieldCheck className="text-gold" />SecureChain</div><p className="mt-1 text-xs text-mute">AI-Driven Software Dependency Threat Detection</p><p className="mt-4 text-xl font-semibold">{reg ? 'Create Account' : 'Welcome Back'}</p></div>
    <form onSubmit={submit} noValidate className="space-y-4">
      {reg && <div><label className="text-sm text-mute">Full Name</label><input required value={f.name} onChange={set('name')} className={box} /></div>}
      <div><label className="text-sm text-mute">Email</label><input required type="email" value={f.email} onChange={set('email')} className={box} />{emailBad && <p className="mt-1 text-xs text-crit">Please enter a valid email address.</p>}</div>
      <PasswordField label="Password" value={f.password} onChange={set('password')} showRules={reg} />
      {reg && <div><PasswordField label="Confirm Password" value={f.confirm} onChange={set('confirm')} />{mismatch && <p className="mt-1 text-xs text-crit">Passwords do not match.</p>}</div>}
      <Button type="submit" disabled={busy || (reg && (!ok || f.password !== f.confirm))} className="w-full disabled:opacity-50">{busy ? 'Please wait…' : reg ? 'Create Account' : 'Sign In'}</Button></form>
    <p className="mt-5 text-sm text-mute">{reg ? <Link to="/login" className="hover:text-gold">Already have an account? Sign in</Link> : <Link to="/register" className="hover:text-gold">Don't have an account? Register</Link>}</p></Card></div>
}
