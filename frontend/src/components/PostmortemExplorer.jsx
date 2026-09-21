import React from 'react';
import { 
  HardDrive, 
  FolderArchive, 
  Clock, 
  FileCode, 
  AlertTriangle, 
  Trash2, 
  Database,
  FileCheck
} from 'lucide-react';

export default function PostmortemExplorer({ filesystemData, prefetchData }) {
  const files = filesystemData || [];
  const prefetch = prefetchData || [];

  const remnantCount = files.filter(f => f.is_uninstalled_remnant).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Remnant Insight Card */}
      <div className="glass-panel" style={{ 
        padding: '1.25rem 1.5rem', 
        borderLeft: '4px solid var(--amber)',
        background: 'rgba(245, 158, 11, 0.07)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ 
            width: '42px', height: '42px', borderRadius: '50%', 
            background: 'rgba(245, 158, 11, 0.2)', display: 'flex', 
            alignItems: 'center', justifyContent: 'center' 
          }}>
            <Trash2 size={22} color="var(--amber)" />
          </div>
          <div>
            <h4 style={{ color: '#fef3c7' }}>Postmortem Data Remnants Identified ({remnantCount})</h4>
            <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)' }}>
              Standard Windows uninstallers do not remove user application data folders in <code>%APPDATA%</code>.
              Wallets, logs, and databases remain accessible post-uninstall.
            </p>
          </div>
        </div>
        <span className="badge badge-amber">Forensic Remnant Finding</span>
      </div>

      {/* Persistent Wallet Files Table */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-highlight)' }}>
            <FolderArchive size={18} color="var(--cyan)" />
            Discovered Wallet Files & Databases ({files.length})
          </h4>
          <span className="badge badge-cyan">File System Triage</span>
        </div>

        {files.length > 0 ? (
          <div className="table-wrapper">
            <table className="forensic-table">
              <thead>
                <tr>
                  <th>Client</th>
                  <th>File Name</th>
                  <th>Format / Header</th>
                  <th>Size</th>
                  <th>Path</th>
                  <th>Modified Timestamp</th>
                  <th>Artifact Nature</th>
                </tr>
              </thead>
              <tbody>
                {files.map((file, idx) => (
                  <tr key={idx}>
                    <td><strong>{file.wallet_name}</strong></td>
                    <td>
                      <span className="mono" style={{ color: 'var(--cyan)' }}>{file.file_name}</span>
                    </td>
                    <td>
                      <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>
                        {file.format_analysis?.format || 'BINARY'}
                      </span>
                    </td>
                    <td className="mono">{file.file_size_bytes ? `${Math.round(file.file_size_bytes / 1024)} KB` : 'N/A'}</td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }} title={file.file_path}>
                        {file.file_path}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: '0.78rem' }}>
                      {file.timestamps?.modified || 'N/A'}
                    </td>
                    <td>
                      {file.is_uninstalled_remnant ? (
                        <span className="badge badge-amber">REMNANT (UNINSTALLED)</span>
                      ) : (
                        <span className="badge badge-emerald">ACTIVE DISK ARTIFACT</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.88rem' }}>
            No cryptocurrency files found in scanned directories. Run the benchmark scan to review sample Berkeley DB and Electrum remnants.
          </div>
        )}
      </div>

      {/* Windows Prefetch Table */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-highlight)' }}>
            <Clock size={18} color="var(--indigo)" />
            Windows Prefetch Execution Artifacts ({prefetch.length})
          </h4>
          <span className="badge badge-cyan">Execution Evidence</span>
        </div>

        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
          Prefetch files prove whether a wallet executable was ever launched on this machine, even if the binary was subsequently deleted by the user.
        </p>

        {prefetch.length > 0 ? (
          <div className="table-wrapper">
            <table className="forensic-table">
              <thead>
                <tr>
                  <th>Prefetch File</th>
                  <th>Target Executable</th>
                  <th>File Size</th>
                  <th>Execution Window (Estimate)</th>
                  <th>Prefetch Path</th>
                </tr>
              </thead>
              <tbody>
                {prefetch.map((pf, pIdx) => (
                  <tr key={pIdx}>
                    <td>
                      <span className="mono" style={{ color: 'var(--indigo)' }}>{pf.file_name}</span>
                    </td>
                    <td><strong>{pf.wallet_binary}</strong></td>
                    <td className="mono">{pf.file_size ? `${pf.file_size} B` : 'N/A'}</td>
                    <td className="mono" style={{ color: 'var(--cyan)' }}>
                      {pf.last_execution_estimate || 'Recorded'}
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.76rem', color: 'var(--text-dim)' }}>
                        {pf.file_path}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.88rem' }}>
            No Prefetch records discovered or administrator privileges required to access <code>C:\Windows\Prefetch</code>.
          </div>
        )}
      </div>

    </div>
  );
}
