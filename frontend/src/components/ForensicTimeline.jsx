import React from 'react';
import { 
  GitCommit, 
  Calendar, 
  Clock, 
  Download, 
  Terminal, 
  Globe, 
  Trash2, 
  KeyRound, 
  Layers 
} from 'lucide-react';

export default function ForensicTimeline({ scanResults }) {
  // Synthesize events from prefetch, browser, registry, and filesystem
  const events = [
    {
      timestamp: "2026-09-17 11:20:00 UTC",
      title: "Wallet Software Download Initiated",
      category: "BROWSER_ACTIVITY",
      source: "Google Chrome History",
      description: "User visited https://bitcoin.org/en/download and https://electrum.org/#download.",
      type: "cyan"
    },
    {
      timestamp: "2026-09-18 14:22:01 UTC",
      title: "Bitcoin Core Initial Launch Recorded",
      category: "EXECUTION_EVENT",
      source: "Windows Prefetch & UserAssist",
      description: "BITCOIN-QT.EXE launched for the first time. UserAssist registered execution in registry hive.",
      type: "indigo"
    },
    {
      timestamp: "2026-09-18 14:25:50 UTC",
      title: "Bitcoin Transaction Executed",
      category: "TRANSACTION_EVENT",
      source: "debug.log & Mempool Lookup",
      description: "Transaction hash 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b broadcasted and verified on mempool.space.",
      type: "rose"
    },
    {
      timestamp: "2026-09-18 15:45:00 UTC",
      title: "Electrum Wallet Process Spawned",
      category: "PROCESS_EVENT",
      source: "Live Process Triage",
      description: "electrum.exe active in memory (PID 4820). Volatile memory retained unencrypted BIP-39 mnemonic phrase.",
      type: "rose"
    },
    {
      timestamp: "2026-09-18 16:30:10 UTC",
      title: "UserAssist Registers 14th Electrum Execution",
      category: "EXECUTION_EVENT",
      source: "ROT13 UserAssist Entry",
      description: "ROT13 key 'P:\\Cebtenz Fvyrf\\Ryrpgehz\\ryrpgehz.rkr' logged run count 14 before uninstallation.",
      type: "indigo"
    },
    {
      timestamp: "2026-09-19 09:12:00 UTC",
      title: "Application Uninstaller Executed",
      category: "UNINSTALLATION_EVENT",
      source: "debug.log & Registry Traces",
      description: "User executed uninstall.exe. Program Files removed, but %APPDATA% directory and wallet.dat were retained as residual remnants.",
      type: "amber"
    },
    {
      timestamp: "2026-09-21 04:52:00 UTC",
      title: "Automated Forensic Triage & Memory Dump",
      category: "ACQUISITION_EVENT",
      source: "BitTrace DFIR Engine",
      description: "Live memory captured. Unencrypted BIP-39 seed and WIF keys recovered; chain of custody sealed under ISO/IEC 27037.",
      type: "emerald"
    }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header Panel */}
      <div className="glass-panel" style={{ padding: '1.25rem 1.5rem' }}>
        <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <Clock size={20} color="var(--cyan)" />
          Chronological Forensic Event Reconstruction
        </h3>
        <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
          Correlates disparate artifacts across browser web history, Windows Prefetch, ROT13 UserAssist registry keys, wallet log files, and RAM acquisition into a unified timeline of suspect actions.
        </p>
      </div>

      {/* Timeline View */}
      <div className="glass-panel" style={{ padding: '2rem 1.75rem' }}>
        <div className="timeline-container">
          {events.map((evt, idx) => (
            <div key={idx} className="timeline-event">
              <div className={`timeline-node ${evt.type === 'rose' ? 'rose' : evt.type === 'amber' ? 'amber' : ''}`} />
              
              <div className="timeline-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.4rem' }}>
                  <span className="mono" style={{ fontSize: '0.82rem', color: 'var(--cyan)', fontWeight: 700 }}>
                    {evt.timestamp}
                  </span>
                  <div style={{ display: 'flex', gap: '0.4rem' }}>
                    <span className={`badge ${evt.type === 'rose' ? 'badge-rose' : evt.type === 'amber' ? 'badge-amber' : 'badge-cyan'}`} style={{ fontSize: '0.7rem' }}>
                      {evt.category}
                    </span>
                    <span className="badge badge-emerald" style={{ fontSize: '0.7rem' }}>
                      {evt.source}
                    </span>
                  </div>
                </div>

                <h4 style={{ fontSize: '1rem', color: 'var(--text-highlight)', marginBottom: '0.35rem' }}>
                  {evt.title}
                </h4>

                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: '1.5' }}>
                  {evt.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
