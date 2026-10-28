import { Navigate, Route, Routes } from "react-router-dom";
import { CommandPalette } from "./components/CommandPalette";
import { Shell } from "./components/Shell";
import { Dossier } from "./pages/Dossier";
import { Launch } from "./pages/Launch";
import { LiveJob } from "./pages/LiveJob";
import { OpsDossier } from "./pages/OpsDossier";

export default function App() {
  return (
    <Shell>
      <CommandPalette />
      <Routes>
        <Route path="/" element={<Launch />} />
        <Route path="/jobs/:jobId" element={<LiveJob />} />
        <Route path="/runs/:runId" element={<Dossier />} />
        <Route path="/runs/:runId/ops" element={<OpsDossier />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  );
}
