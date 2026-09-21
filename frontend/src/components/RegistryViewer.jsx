import React from 'react';
import { 
  FileCode, 
  Terminal, 
  RotateCw, 
  Layers, 
  ExternalLink, 
  CheckCircle2, 
  Clock, 
  ShieldAlert 
} from 'lucide-react';

export default function RegistryViewer({ registryData }) {
  const userassist = registryData?.userassist_executions || [];
  const installed = registryData?.installed_software || [];
  const protocols = registryData?.protocol_handlers || [];
  const runKeys = registryData?.autorun_keys || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Educational Banner on ROT13 UserAssist */}
      <div className="glass-panel" style={{ 
        padding: '1.25rem 1.5rem', 
        borderLeft: '4px solid var(--cyan)',
        background: 'rgba(0, 240, 255, 0.05)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ 
            width: '42px', height: '42px', borderRadius: '50%', 
            background: 'rgba(0, 240, 255, 0.15)', display: 'flex', 
            alignItems: 'center', justifyContent: 'center' 
          }}>
            <RotateCw size={22} color="var(--cyan)" />
          </div>
          <div>
            <h4 style={{ color: '#e0f2fe' }}>Windows UserAssist ROT13 Forensic Decoder</h4>
            <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)' }}>
              Windows logs user program executions in the registry encoded using ROT13 encryption.
              Our engine decrypts the executable paths, unpacks the 72-byte binary structures, and extracts run counts and FILETIME timestamps.
            </p>
          </div>
        </div>
        <span className="badge badge-cyan">Registry Evidential Value: HIGH</span>
      </div>

      {/* UserAssist Decoded Table */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-highlight)' }}>
            <Clock size={18} color="var(--cyan)" />
            Decoded UserAssist Execution History ({userassist.length})
          </h4>
          <span className="badge badge-cyan">ROT13 Decrypted</span>
        </div>

        {userassist.length > 0 ? (
          <div className="table-wrapper">
            <table className="forensic-table">
              <thead>
                <tr>
                  <th>Decoded Executable Path</th>
                  <th>Raw ROT13 Registry Key</th>
                  <th>Execution Count</th>
                  <th>Last Run Timestamp (UTC)</th>
                  <th>Category</th>
                </tr>
              </thead>
              <tbody>
                {userassist.map((ua, idx) => (
                  <tr key={idx}>
                    <td>
                      <strong className="mono" style={{ color: 'var(--cyan)' }}>
                        {ua.decoded_path}
                      </strong>
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                        {ua.raw_rot13_name}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-cyan">{ua.run_count} Launches</span>
                    </td>
                    <td className="mono" style={{ color: 'var(--text-main)', fontSize: '0.82rem' }}>
                      {ua.last_executed}
                    </td>
                    <td>
                      <span className="badge badge-rose">CRYPTOCURRENCY CLIENT</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.88rem' }}>
            No cryptocurrency executables detected in UserAssist registry hives. Run the IEEE benchmark to view sample ROT13 decrypted data.
          </div>
        )}
      </div>

      {/* Installed & Residual Uninstall Keys */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-highlight)' }}>
            <Layers size={18} color="var(--amber)" />
            Registry Uninstall Key Traces ({installed.length})
          </h4>
          <span className="badge badge-amber">Remnant Identification</span>
        </div>

        {installed.length > 0 ? (
          <div className="table-wrapper">
            <table className="forensic-table">
              <thead>
                <tr>
                  <th>Application Name</th>
                  <th>Version</th>
                  <th>Install Location</th>
                  <th>Registry Path</th>
                  <th>Disk Presence</th>
                </tr>
              </thead>
              <tbody>
                {installed.map((app, idx) => (
                  <tr key={idx}>
                    <td><strong>{app.application_name}</strong></td>
                    <td className="mono">{app.version}</td>
                    <td className="mono" style={{ fontSize: '0.78rem' }}>{app.install_location}</td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                        {app.registry_path}
                      </span>
                    </td>
                    <td>
                      {app.is_remnant ? (
                        <span className="badge badge-amber">RESIDUAL UNINSTALL REMNANT</span>
                      ) : (
                        <span className="badge badge-emerald">ACTIVE ON DISK</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.88rem' }}>
            No cryptocurrency software entries detected in Windows Uninstall keys.
          </div>
        )}
      </div>

      {/* Protocol Handlers & Run Keys */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.5rem' }}>
        {/* Protocol Handlers */}
        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <h4 style={{ fontSize: '0.95rem', marginBottom: '0.75rem', color: 'var(--text-highlight)' }}>
            URL Protocol Handlers (URI Schemes)
          </h4>
          {protocols.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {protocols.map((p, pIdx) => (
                <div key={pIdx} style={{ 
                  background: 'rgba(0, 0, 0, 0.4)', 
                  padding: '0.75rem', 
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)' 
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="badge badge-cyan">{p.protocol}</span>
                    <span className="badge badge-amber" style={{ fontSize: '0.7rem' }}>{p.status}</span>
                  </div>
                  <div className="mono" style={{ fontSize: '0.78rem', marginTop: '0.4rem', color: 'var(--text-muted)' }}>
                    Command: {p.command}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: 'var(--text-dim)', fontSize: '0.82rem' }}>
              No custom <code>bitcoin://</code> URL protocol handlers registered in HKCR.
            </p>
          )}
        </div>

        {/* Autorun Keys */}
        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <h4 style={{ fontSize: '0.95rem', marginBottom: '0.75rem', color: 'var(--text-highlight)' }}>
            Autorun / Persistence Keys (Run / RunOnce)
          </h4>
          {runKeys.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {runKeys.map((rk, rIdx) => (
                <div key={rIdx} style={{ 
                  background: 'rgba(0, 0, 0, 0.4)', 
                  padding: '0.75rem', 
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)' 
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <strong style={{ fontSize: '0.82rem' }}>{rk.name}</strong>
                    <span className="badge badge-cyan">{rk.hive}</span>
                  </div>
                  <div className="mono" style={{ fontSize: '0.78rem', marginTop: '0.4rem', color: 'var(--text-muted)' }}>
                    {rk.command}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: 'var(--text-dim)', fontSize: '0.82rem' }}>
              No persistent auto-start registry entries found under <code>Software\Microsoft\Windows\CurrentVersion\Run</code>.
            </p>
          )}
        </div>
      </div>

    </div>
  );
}
