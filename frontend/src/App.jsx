import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import OverviewDashboard from './components/OverviewDashboard';
import LiveMemoryInspector from './components/LiveMemoryInspector';
import PostmortemExplorer from './components/PostmortemExplorer';
import RegistryViewer from './components/RegistryViewer';
import BrowserForensics from './components/BrowserForensics';
import ForensicTimeline from './components/ForensicTimeline';
import EvidenceLedger from './components/EvidenceLedger';
import ReportModal from './components/ReportModal';
import LiveScanConsole from './components/LiveScanConsole';

import { 
  LayoutDashboard, 
  Cpu, 
  FolderArchive, 
  RotateCw, 
  Globe, 
  Clock, 
  ShieldCheck,
  Terminal,
  ChevronUp,
  ChevronDown
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [systemProfile, setSystemProfile] = useState(null);
  const [scanResults, setScanResults] = useState(null);
  const [evidenceLedger, setEvidenceLedger] = useState(null);
  const [reportData, setReportData] = useState(null);
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [telemetryLogs, setTelemetryLogs] = useState([]);
  const [showConsole, setShowConsole] = useState(true);

  // Fetch system profile and initial state on mount
  useEffect(() => {
    fetchProfile();
    fetchLedger();
    // Auto-load sample benchmark on start so user immediately has full data
    runSampleScan();
  }, []);

  const fetchProfile = async () => {
    try {
      const res = await fetch('/api/system/profile');
      if (res.ok) {
        const data = await res.json();
        setSystemProfile(data);
      }
    } catch (e) {
      console.warn('Backend server connecting...');
    }
  };

  const fetchLedger = async () => {
    try {
      const res = await fetch('/api/evidence/ledger');
      if (res.ok) {
        const data = await res.json();
        setEvidenceLedger(data);
      }
    } catch (e) {
      console.warn('Evidence ledger pending...');
    }
  };

  const startWebSocketTelemetry = () => {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/live-scan`;
      const ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const log = JSON.parse(event.data);
          setTelemetryLogs((prev) => [...prev.slice(-40), log]);
        } catch (err) {
          console.error(err);
        }
      };

      ws.onerror = () => ws.close();
      return ws;
    } catch (e) {
      return null;
    }
  };

  const runLiveScan = async () => {
    setLoading(true);
    setTelemetryLogs([]);
    startWebSocketTelemetry();

    try {
      const res = await fetch('/api/scan/live', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setScanResults(data);
        await fetchLedger();
      }
    } catch (e) {
      console.error('Live scan failed', e);
    } finally {
      setLoading(false);
    }
  };

  const runSampleScan = async () => {
    setLoading(true);
    setTelemetryLogs([]);
    startWebSocketTelemetry();

    try {
      const res = await fetch('/api/scan/sample', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setScanResults(data);
        await fetchLedger();
      }
    } catch (e) {
      console.error('Benchmark scan failed', e);
    } finally {
      setLoading(false);
    }
  };

  const uploadMemoryDump = async (file) => {
    setIsUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/scan/memory-dump', {
        method: 'POST',
        body: formData,
      });
      if (res.ok) {
        const memData = await res.json();
        setScanResults((prev) => ({
          ...prev,
          volatile_memory: memData,
        }));
        await fetchLedger();
        setActiveTab('memory');
      }
    } catch (e) {
      console.error('Memory dump upload failed', e);
    } finally {
      setIsUploading(false);
    }
  };

  const verifyEvidence = async (evidenceId) => {
    const formData = new FormData();
    formData.append('evidence_id', evidenceId);

    const res = await fetch('/api/evidence/verify', {
      method: 'POST',
      body: formData,
    });
    return await res.json();
  };

  const openReport = async () => {
    try {
      const res = await fetch('/api/report/generate');
      if (res.ok) {
        const rep = await res.json();
        setReportData(rep);
        setIsReportOpen(true);
      }
    } catch (e) {
      console.error('Report generation failed', e);
    }
  };

  const totalVolatile =
    (scanResults?.volatile_memory?.seeds?.length || 0) +
    (scanResults?.volatile_memory?.private_keys?.length || 0);
  const totalRemnants = scanResults?.metrics?.uninstalled_remnants || 0;
  const totalUserassist =
    scanResults?.registry?.userassist_executions?.length || 0;
  const totalBrowser = scanResults?.browser?.total_records_found || 0;
  const totalEvidence = evidenceLedger?.total_items || 0;

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navigation */}
      <Header
        systemProfile={systemProfile}
        onRunLiveScan={runLiveScan}
        onRunSampleScan={runSampleScan}
        onOpenReport={openReport}
        loading={loading}
        activeMode={scanResults?.mode}
      />

      {/* Secondary Navigation Tabs */}
      <nav className="tabs-bar">
        <button
          className={`tab-button ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          <LayoutDashboard size={16} />
          <span>Mission Overview</span>
        </button>

        <button
          className={`tab-button ${activeTab === 'memory' ? 'active' : ''}`}
          onClick={() => setActiveTab('memory')}
        >
          <Cpu size={16} />
          <span>Live RAM Forensics</span>
          {totalVolatile > 0 && <span className="tab-badge">{totalVolatile}</span>}
        </button>

        <button
          className={`tab-button ${activeTab === 'postmortem' ? 'active' : ''}`}
          onClick={() => setActiveTab('postmortem')}
        >
          <FolderArchive size={16} />
          <span>File System & Remnants</span>
          {totalRemnants > 0 && <span className="tab-badge">{totalRemnants}</span>}
        </button>

        <button
          className={`tab-button ${activeTab === 'registry' ? 'active' : ''}`}
          onClick={() => setActiveTab('registry')}
        >
          <RotateCw size={16} />
          <span>Registry & UserAssist</span>
          {totalUserassist > 0 && <span className="tab-badge">{totalUserassist}</span>}
        </button>

        <button
          className={`tab-button ${activeTab === 'browser' ? 'active' : ''}`}
          onClick={() => setActiveTab('browser')}
        >
          <Globe size={16} />
          <span>Browser & Web Wallets</span>
          {totalBrowser > 0 && <span className="tab-badge">{totalBrowser}</span>}
        </button>

        <button
          className={`tab-button ${activeTab === 'timeline' ? 'active' : ''}`}
          onClick={() => setActiveTab('timeline')}
        >
          <Clock size={16} />
          <span>Forensic Timeline</span>
        </button>

        <button
          className={`tab-button ${activeTab === 'ledger' ? 'active' : ''}`}
          onClick={() => setActiveTab('ledger')}
        >
          <ShieldCheck size={16} />
          <span>Chain of Custody</span>
          {totalEvidence > 0 && <span className="tab-badge">{totalEvidence}</span>}
        </button>
      </nav>

      {/* Main Content Area */}
      <main className="app-container" style={{ flex: 1 }}>
        {activeTab === 'overview' && (
          <OverviewDashboard
            scanResults={scanResults}
            onNavigateTab={(tab) => setActiveTab(tab)}
          />
        )}

        {activeTab === 'memory' && (
          <LiveMemoryInspector
            volatileData={scanResults?.volatile_memory}
            processes={scanResults?.processes}
            onUploadMemoryDump={uploadMemoryDump}
            isUploading={isUploading}
          />
        )}

        {activeTab === 'postmortem' && (
          <PostmortemExplorer
            filesystemData={scanResults?.filesystem}
            prefetchData={scanResults?.prefetch}
          />
        )}

        {activeTab === 'registry' && (
          <RegistryViewer registryData={scanResults?.registry} />
        )}

        {activeTab === 'browser' && (
          <BrowserForensics browserData={scanResults?.browser} />
        )}

        {activeTab === 'timeline' && (
          <ForensicTimeline scanResults={scanResults} />
        )}

        {activeTab === 'ledger' && (
          <EvidenceLedger
            evidenceLedger={evidenceLedger}
            onVerifyEvidence={verifyEvidence}
          />
        )}

        {/* Live Acquisition Console Pane */}
        <div style={{ marginTop: '1rem' }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              cursor: 'pointer',
              padding: '0.4rem 0.2rem',
              color: 'var(--text-dim)',
              fontSize: '0.8rem',
            }}
            onClick={() => setShowConsole(!showConsole)}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Terminal size={14} color="var(--cyan)" />
              {showConsole ? 'Hide Acquisition Telemetry' : 'Show Acquisition Telemetry'}
            </span>
            {showConsole ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </div>

          {showConsole && (
            <div style={{ marginTop: '0.4rem' }}>
              <LiveScanConsole logs={telemetryLogs} isActive={loading} />
            </div>
          )}
        </div>
      </main>

      {/* Court-Ready Report Modal */}
      {isReportOpen && (
        <ReportModal
          reportData={reportData}
          onClose={() => setIsReportOpen(false)}
        />
      )}
    </div>
  );
}
