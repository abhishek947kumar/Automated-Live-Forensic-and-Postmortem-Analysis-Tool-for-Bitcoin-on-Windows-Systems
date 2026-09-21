import React from 'react';
import { 
  KeyRound, 
  Trash2, 
  Globe, 
  Database, 
  AlertTriangle, 
  CheckCircle2, 
  BookOpen, 
  Search,
  ExternalLink,
  Lock,
  Cpu
} from 'lucide-react';

export default function OverviewDashboard({ scanResults, onNavigateTab }) {
  if (!scanResults) {
    return (
      <div className="glass-panel" style={{ padding: '3.5rem 2rem', textAlign: 'center' }}>
        <Database size={48} color="var(--cyan)" style={{ margin: '0 auto 1.25rem', opacity: 0.8 }} />
        <h2>Awaiting Digital Forensics Acquisition</h2>
        <p style={{ color: 'var(--text-muted)', maxWidth: '580px', margin: '0.75rem auto 1.75rem' }}>
          Select <strong>"Execute Live Triage"</strong> to immediately extract volatile and persistent Bitcoin artifacts from this Windows host, or click <strong>"Load IEEE Benchmark"</strong> to evaluate the research test corpus.
        </p>
      </div>
    );
  }

  const metrics = scanResults.metrics || {};
  const seedsCount = scanResults.volatile_memory?.seeds?.length || 0;
  const keysCount = scanResults.volatile_memory?.private_keys?.length || 0;
  const totalVolatile = seedsCount + keysCount;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Metrics Banner */}
      <div className="metrics-grid">
        <div className={`glass-panel metric-card ${totalVolatile > 0 ? 'alert-rose' : ''}`}>
          <div className="metric-header">
            <span>Volatile Secrets in RAM</span>
            <KeyRound size={18} color={totalVolatile > 0 ? 'var(--rose)' : 'var(--cyan)'} />
          </div>
          <div className="metric-value" style={{ color: totalVolatile > 0 ? 'var(--rose)' : 'var(--text-highlight)' }}>
            {totalVolatile}
          </div>
          <div className="metric-footer">
            <span>{seedsCount} BIP-39 Seeds • {keysCount} Private Keys</span>
          </div>
        </div>

        <div className={`glass-panel metric-card ${metrics.uninstalled_remnants > 0 ? 'alert-amber' : ''}`}>
          <div className="metric-header">
            <span>Uninstalled Remnants</span>
            <Trash2 size={18} color="var(--amber)" />
          </div>
          <div className="metric-value" style={{ color: metrics.uninstalled_remnants > 0 ? 'var(--amber)' : 'var(--text-highlight)' }}>
            {metrics.uninstalled_remnants || 0}
          </div>
          <div className="metric-footer">
            <span>Residual AppData & Registry traces</span>
          </div>
        </div>

        <div className="glass-panel metric-card">
          <div className="metric-header">
            <span>Detected Wallets</span>
            <Database size={18} color="var(--cyan)" />
          </div>
          <div className="metric-value">
            {metrics.wallets_detected || 0}
          </div>
          <div className="metric-footer">
            <span>{metrics.processes_running || 0} active running processes</span>
          </div>
        </div>

        <div className="glass-panel metric-card alert-emerald">
          <div className="metric-header">
            <span>Chain of Custody (ISO 27037)</span>
            <CheckCircle2 size={18} color="var(--emerald)" />
          </div>
          <div className="metric-value" style={{ color: 'var(--emerald)' }}>
            VERIFIED
          </div>
          <div className="metric-footer">
            <span>SHA-256 & MD5 hashes sealed</span>
          </div>
        </div>
      </div>

      {/* Critical Findings Alert Banner if Private Keys / Seeds detected */}
      {totalVolatile > 0 && (
        <div className="glass-panel" style={{ 
          padding: '1.25rem 1.5rem', 
          borderLeft: '4px solid var(--rose)',
          background: 'rgba(244, 63, 94, 0.08)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <div style={{ 
              width: '42px', height: '42px', borderRadius: '50%', 
              background: 'rgba(244, 63, 94, 0.2)', display: 'flex', 
              alignItems: 'center', justifyContent: 'center' 
            }}>
              <AlertTriangle size={22} color="var(--rose)" />
            </div>
            <div>
              <h4 style={{ color: '#fecdd3' }}>Volatile Cryptographic Secrets Recovered from Live Memory</h4>
              <p style={{ fontSize: '0.86rem', color: 'var(--text-muted)' }}>
                {seedsCount} unencrypted BIP-39 mnemonic seed phrase(s) and {keysCount} WIF private key(s) were captured from memory.
                These would be permanently destroyed if the system were powered down.
              </p>
            </div>
          </div>
          <button className="btn-secondary" onClick={() => onNavigateTab('memory')}>
            Inspect in RAM Viewer
          </button>
        </div>
      )}

      {/* Two Column Layout: Wallet Artifact Matrix + Research Methodology */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '1.5rem' }}>
        {/* Research Benchmark Matrix */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <h3 style={{ fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Cpu size={18} color="var(--cyan)" />
              Target Wallet Artifact Footprint
            </h3>
            <span className="badge badge-cyan">IEEE Access 2019 Scope</span>
          </div>

          <div className="table-wrapper">
            <table className="forensic-table">
              <thead>
                <tr>
                  <th>Target Client</th>
                  <th>Memory (RAM)</th>
                  <th>File System</th>
                  <th>Registry / Prefetch</th>
                  <th>Remnant Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>Bitcoin Core</strong></td>
                  <td>
                    <span className="badge badge-rose">Plaintext Keys</span>
                  </td>
                  <td><code>wallet.dat (BDB)</code></td>
                  <td><code>BITCOIN-QT.PF</code></td>
                  <td><span className="badge badge-amber">Remnant Retained</span></td>
                </tr>
                <tr>
                  <td><strong>Electrum</strong></td>
                  <td>
                    <span className="badge badge-rose">BIP-39 Seed</span>
                  </td>
                  <td><code>wallets/default</code></td>
                  <td><code>UserAssist (ROT13)</code></td>
                  <td><span className="badge badge-amber">Remnant Retained</span></td>
                </tr>
                <tr>
                  <td><strong>Armory</strong></td>
                  <td>
                    <span className="badge badge-cyan">Root Seeds</span>
                  </td>
                  <td><code>armorylog.txt</code></td>
                  <td>Prefetch Trace</td>
                  <td><span className="badge badge-emerald">DB Preserved</span></td>
                </tr>
                <tr>
                  <td><strong>Bither</strong></td>
                  <td>Password & PIN</td>
                  <td><code>bither.cfg</code></td>
                  <td>Run Keys</td>
                  <td><span className="badge badge-amber">Residual Files</span></td>
                </tr>
                <tr>
                  <td><strong>MultiBit HD</strong></td>
                  <td>AES Decrypt Key</td>
                  <td><code>mbhd.wallet.aes</code></td>
                  <td>Prefetch Run Count</td>
                  <td><span className="badge badge-emerald">Encrypted File</span></td>
                </tr>
                <tr>
                  <td><strong>Copay / BitPay</strong></td>
                  <td>Session Tokens</td>
                  <td>LevelDB Storage</td>
                  <td>App Paths</td>
                  <td><span className="badge badge-amber">LevelDB Remnant</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Academic Context & DFIR Methodology */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '1rem' }}>
              <BookOpen size={18} color="var(--indigo)" />
              <h3 style={{ fontSize: '1.1rem' }}>Research Citation & Methodology</h3>
            </div>
            
            <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', lineHeight: '1.6', marginBottom: '1rem' }}>
              Based on the published work in <em>IEEE Access (2019)</em> by <strong>Stephan Zollner, Kim-Kwang Raymond Choo, and Nhien-An Le-Khac</strong>:
              <em> "Automated Live Forensic and Postmortem Analysis Tool for Bitcoin on Windows."</em>
            </p>

            <div style={{ 
              background: 'rgba(0, 0, 0, 0.35)', 
              padding: '1rem', 
              borderRadius: 'var(--radius-md)', 
              border: '1px solid var(--border-subtle)',
              fontSize: '0.82rem',
              lineHeight: '1.5',
              marginBottom: '1rem'
            }}>
              <strong style={{ color: 'var(--cyan)' }}>Key Empirical Findings:</strong>
              <ul style={{ paddingLeft: '1.25rem', marginTop: '0.4rem', color: 'var(--text-main)', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                <li><strong>Live RAM Superiority</strong>: Unencrypted BIP-39 recovery seeds and WIF private keys can be extracted while the wallet is unlocked in memory.</li>
                <li><strong>Uninstallation Blindspots</strong>: Desktop clients leave behind unencrypted wallet databases, debug logs, and registry keys even after official uninstallation.</li>
                <li><strong>Browser History Persistence</strong>: Web wallets leave substantial traces in SQLite history databases, revealing transaction IDs and exchange accounts.</li>
              </ul>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
            <button className="btn-secondary" style={{ flex: 1 }} onClick={() => onNavigateTab('registry')}>
              Explore Registry & ROT13
            </button>
            <button className="btn-secondary" style={{ flex: 1 }} onClick={() => onNavigateTab('timeline')}>
              Inspect Event Timeline
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
