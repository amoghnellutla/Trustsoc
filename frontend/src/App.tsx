import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Overview from './pages/Overview'
import Alerts from './pages/Alerts'
import Incidents from './pages/Incidents'
import MitreHeatmap from './pages/MitreHeatmap'
import EvidenceViewer from './pages/EvidenceViewer'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/mitre" element={<MitreHeatmap />} />
        <Route path="/evidence" element={<EvidenceViewer />} />
      </Routes>
    </Layout>
  )
}
