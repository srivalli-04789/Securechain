import { Routes, Route, Navigate } from 'react-router-dom'
import AppLayout from './layouts/AppLayout'
import Auth from './pages/Auth'
import Dashboard from './pages/Dashboard'
import { Projects } from './pages/DataPages'
import NewScan from './pages/NewScan'
import ScanProgress from './pages/ScanProgress'
import ScanResults from './pages/ScanResults'
import { Overview } from './pages/ScanTabs'
import { ScanSBOM, ScanVulns, AIRisk, Recs, GraphTab, Threats, ReportTab } from './pages/ScanTabsLive'
import { Settings, Profile } from './pages/Account'
export default function App() {
  return <Routes>
    <Route path="/" element={<Auth mode="login" />} /><Route path="/login" element={<Auth mode="login" />} /><Route path="/register" element={<Auth mode="register" />} />
    <Route element={<AppLayout />}>
      <Route path="/dashboard" element={<Dashboard />} /><Route path="/projects" element={<Projects />} /><Route path="/scans/new" element={<NewScan />} /><Route path="/scans/:id/progress" element={<ScanProgress />} />
      <Route path="/scans/:id" element={<ScanResults />}><Route index element={<Overview />} /><Route path="sbom" element={<ScanSBOM />} /><Route path="vulnerabilities" element={<ScanVulns />} /><Route path="graph" element={<GraphTab />} /><Route path="ai-risk" element={<AIRisk />} /><Route path="threats" element={<Threats />} /><Route path="recommendations" element={<Recs />} /><Route path="report" element={<ReportTab />} /></Route>
      <Route path="/settings" element={<Settings />} /><Route path="/profile" element={<Profile />} />
    </Route><Route path="*" element={<Navigate to="/" />} /></Routes>
}
