import React, { lazy, Suspense, useEffect, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Shield,
  ShieldAlert,
} from "lucide-react";
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useParams,
  useNavigate,
} from "react-router-dom";
import { fetchHealth } from "./api/client";
import { LoadingSpinner } from "./components/LoadingSpinner";
import { Sidebar } from "./components/Sidebar";
import type { HealthResponse } from "./types";

const Dashboard = lazy(() => import("./pages/Dashboard").then((module) => ({ default: module.Dashboard })));
const Findings = lazy(() => import("./pages/Findings").then((module) => ({ default: module.Findings })));
const NewScan = lazy(() => import("./pages/NewScan").then((module) => ({ default: module.NewScan })));
const ScanDetail = lazy(() => import("./pages/ScanDetail").then((module) => ({ default: module.ScanDetail })));
const ScanHistory = lazy(() => import("./pages/ScanHistory").then((module) => ({ default: module.ScanHistory })));
const About = lazy(() => import("./pages/About").then((module) => ({ default: module.About })));

const AppLayout: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    let active = true;
    const refreshHealth = async () => {
      try {
        const result = await fetchHealth();
        if (active) {
          setHealth(result);
          setHealthError(null);
        }
      } catch (error) {
        if (active) {
          setHealthError(error instanceof Error ? error.message : "API unavailable");
        }
      }
    };
    void refreshHealth();
    const timer = window.setInterval(() => void refreshHealth(), 30000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#070A11] text-slate-100">
      <Sidebar />
      <div className="min-h-screen md:ml-60">
        <header className="sticky top-0 z-20 flex items-center justify-between border-b border-slate-800 bg-[#070A11]/90 px-4 py-3 backdrop-blur sm:px-6">
          <button
            type="button"
            className="flex items-center gap-2 text-sm font-bold text-white md:hidden"
            onClick={() => navigate("/")}
          >
            <Shield className="h-5 w-5 text-cyan-400" />
            VulnPath AI
          </button>
          <div className="hidden items-center gap-2 text-xs text-slate-500 md:flex">
            <Activity className="h-4 w-4 text-cyan-400" />
            Local Security Workbench
          </div>
          <div
            className="flex items-center gap-2 text-xs"
            title={healthError ?? `${health?.runtime.python_version ?? "Python"} · loopback API`}
          >
            {healthError ? (
              <ShieldAlert className="h-4 w-4 text-red-400" />
            ) : (
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            )}
            <span className={healthError ? "text-red-300" : "text-slate-300"}>
              {healthError ? "API offline" : "Local engine online"}
            </span>
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl p-4 sm:p-6 lg:p-8">
          <Suspense fallback={<LoadingSpinner message="Loading workbench…" />}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scan/new" element={<NewScan />} />
              <Route path="/scans/:scanId" element={<ScanDetail />} />
              <Route path="/scan/:scanId/findings" element={<LegacyScanRedirect />} />
              <Route path="/history" element={<ScanHistory />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/about" element={<About health={health} />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </main>
      </div>
    </div>
  );
};

const LegacyScanRedirect: React.FC = () => {
  const { scanId = "" } = useParams();
  return <Navigate to={`/scans/${scanId}`} replace />;
};

export const App: React.FC = () => (
  <BrowserRouter>
    <AppLayout />
  </BrowserRouter>
);
