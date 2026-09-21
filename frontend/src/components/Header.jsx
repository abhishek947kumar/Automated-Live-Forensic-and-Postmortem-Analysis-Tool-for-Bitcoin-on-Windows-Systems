import React from 'react';
import { 
  ShieldCheck, 
  Cpu, 
  Play, 
  Layers, 
  FileText, 
  HardDrive,
  RefreshCw,
  AlertCircle
} from 'lucide-react';

export default function Header({ 
  systemProfile, 
  onRunLiveScan, 
  onRunSampleScan, 
  onOpenReport, 
  loading,
  activeMode
}) {
  return (
    <header className="top-nav">
      <div className="nav-brand">
        <div className="nav-logo-icon">
          <ShieldCheck size={26} />
        </div>
        <div>
          <div className="brand-title">BitTrace DFIR</div>
          <div className="brand-subtitle">Automated Live & Postmortem Bitcoin Forensic Lens</div>
        </div>
      </div>

      <div className="nav-case-meta">
        {systemProfile ? (
          <div className="meta-pill">
            <Cpu size={14} color="var(--cyan)" />
            <span>Host: <strong>{systemProfile.hostname || 'TARGET-PC'}</strong></span>
            <span style={{ color: 'var(--text-dim)' }}>|</span>
            <span>{systemProfile.os_name} {systemProfile.os_release}</span>
            <span style={{ color: 'var(--text-dim)' }}>|</span>
            <span className="dot" title="Live Agent Active"></span>
            <span>{systemProfile.ram_usage_percent}% RAM</span>
          </div>
        ) : (
          <div className="meta-pill">
            <AlertCircle size={14} color="var(--amber)" />
            <span>Connecting to Forensic Agent...</span>
          </div>
        )}

        {activeMode && (
          <div className="badge badge-cyan" style={{ fontSize: '0.75rem' }}>
            {activeMode === 'IEEE_ACCESS_BENCHMARK_CASE' ? 'IEEE 2019 Benchmark Case' : 'Live Host Triage'}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
        <button 
          className="btn-secondary" 
          onClick={onRunSampleScan} 
          disabled={loading}
          title="Loads the IEEE Access 2019 research benchmark case: Operation Satoshi Shadow"
        >
          <Layers size={16} color="var(--cyan)" />
          {loading ? 'Processing...' : 'Load IEEE Benchmark'}
        </button>

        <button 
          className="btn-primary" 
          onClick={onRunLiveScan} 
          disabled={loading}
          title="Executes immediate automated live volatile & disk forensics on this Windows system"
        >
          {loading ? <RefreshCw size={16} className="spin" /> : <Play size={16} />}
          {loading ? 'Acquiring...' : 'Execute Live Triage'}
        </button>

        <button 
          className="btn-secondary" 
          onClick={onOpenReport}
          title="Generates a court-ready ISO/IEC 27037 forensic audit report"
        >
          <FileText size={16} color="var(--emerald)" />
          Forensic Report
        </button>
      </div>
    </header>
  );
}
