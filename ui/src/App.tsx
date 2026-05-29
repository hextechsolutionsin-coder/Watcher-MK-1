import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import IncidentDetail from './pages/IncidentDetail';
import ApprovalQueue from './pages/ApprovalQueue';
import ActionsLog from './pages/ActionsLog';
import ExecutiveView from './pages/ExecutiveView';
import PipelineStatus from './pages/PipelineStatus';
import Connectors from './pages/Connectors';

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="approvals" element={<ApprovalQueue />} />
        <Route path="actions" element={<ActionsLog />} />
        <Route path="pipeline" element={<PipelineStatus />} />
        <Route path="connectors" element={<Connectors />} />
        <Route path="executive" element={<ExecutiveView />} />
      </Route>
    </Routes>
  );
}

export default App;
