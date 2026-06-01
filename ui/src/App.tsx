import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import IncidentDetail from './pages/IncidentDetail';
import ApprovalQueue from './pages/ApprovalQueue';
import ActionsLog from './pages/ActionsLog';
import ExecutiveView from './pages/ExecutiveView';
import PipelineStatus from './pages/PipelineStatus';
import Connectors from './pages/Connectors';
import Suppressions from './pages/Suppressions';
import PolledEvents from './pages/PolledEvents';

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
        <Route path="suppressions" element={<Suppressions />} />
        <Route path="events" element={<PolledEvents />} />
        <Route path="executive" element={<ExecutiveView />} />
      </Route>
    </Routes>
  );
}

export default App;
