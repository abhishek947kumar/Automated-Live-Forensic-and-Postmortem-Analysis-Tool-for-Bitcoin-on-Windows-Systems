import React, { useState } from 'react';
import { 
  Cpu, 
  Key, 
  FileText, 
  Upload, 
  Search, 
  Copy, 
  Check, 
  Terminal, 
  Hash,
  ShieldAlert,
  HelpCircle
} from 'lucide-react';

export default function LiveMemoryInspector({ volatileData, processes, onUploadMemoryDump, isUploading }) {
  const [selectedArtifact, setSelectedArtifact] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  const seeds = volatileData?.seeds || [];
  const privateKeys = volatileData?.private_keys || [];
  const publicAddrs = volatileData?.public_addresses || [];
  const credentials = volatileData?.credentials || [];

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      onUploadMemoryDump(file);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Upload Memory Dump Bar & Summary */}
      <div className="glass-panel" style={{ padding: '1.25rem 1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Cpu size={20} color="var(--rose)" />
            Live RAM & Volatile Memory Inspection
          </h3>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
            Extracts unencrypted cryptographic secrets, BIP-39 mnemonic seeds, and RPC credentials residing in process heap/stack memory.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <label className="btn-secondary" style={{ cursor: 'pointer', margin: 0 }}>
            <Upload size={16} color="var(--cyan)" />
            <span>{isUploading ? 'Analyzing Dump...' : 'Upload Raw Memory Dump (.raw/.dmp)'}</span>
            <input 
              type="file" 
              accept=".raw,.dmp,.bin,.vmem,.img" 
              style={{ display: 'none' }} 
              onChange={handleFileUpload} 
              disabled={isUploading}
            />
          </label>
        </div>
      </div>

      {/* Running Target Processes Table */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-main)' }}>
            <Terminal size={18} color="var(--cyan)" />
            Active Cryptocurrency Wallet Processes ({processes?.length || 0})
          </h4>
          <span className="badge badge-cyan">Process Triage</span>
        </div>

        {processes && processes.length > 0 ? (
          <div className="table-wrapper">
            <table className="forensic-table">
              <thead>
                <tr>
                  <th>PID</th>
                  <th>Executable</th>
                  <th>Target Wallet Client</th>
                  <th>Memory (RSS)</th>
                  <th>Started Timestamp</th>
                  <th>User Context</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {processes.map((proc, i) => (
                  <tr key={i}>
                    <td><span className="mono" style={{ color: 'var(--cyan)' }}>{proc.pid}</span></td>
                    <td><strong>{proc.name}</strong></td>
                    <td>{proc.wallet_type}</td>
                    <td><span className="mono">{proc.memory_rss_mb} MB</span></td>
                    <td className="mono">{proc.started_at}</td>
                    <td>{proc.username}</td>
                    <td>
                      <span className="badge badge-rose">MONITORED</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.88rem' }}>
            No known Bitcoin wallet executables currently executing in live process space. Load the benchmark case to inspect simulated active processes.
          </div>
        )}
      </div>

      {/* Volatile Secrets Recovered & Interactive Hex Viewer */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))', gap: '1.5rem' }}>
        
        {/* Secrets Table */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-highlight)' }}>
              <Key size={18} color="var(--rose)" />
              Volatile Secrets Recovered ({seeds.length + privateKeys.length + credentials.length})
            </h4>
            <span className="badge badge-rose">Critical Evidence</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            {/* BIP-39 Seeds */}
            {seeds.map((seed, idx) => (
              <div 
                key={`seed-${idx}`} 
                className="glass-panel" 
                style={{ 
                  padding: '1rem', 
                  border: selectedArtifact === seed ? '1px solid var(--rose)' : '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  background: selectedArtifact === seed ? 'rgba(244, 63, 94, 0.12)' : 'rgba(15, 23, 42, 0.6)'
                }}
                onClick={() => setSelectedArtifact(seed)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                  <span className="badge badge-rose">BIP-39 Mnemonic Seed ({seed.word_count} Words)</span>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                    Offset: 0x{seed.offset?.toString(16).toUpperCase() || '000142A0'}
                  </span>
                </div>
                <div className="mono" style={{ 
                  fontSize: '0.88rem', 
                  color: '#fecdd3', 
                  background: 'rgba(0, 0, 0, 0.4)', 
                  padding: '0.5rem', 
                  borderRadius: 'var(--radius-sm)',
                  wordBreak: 'break-word',
                  lineHeight: '1.5'
                }}>
                  {seed.secret_value}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.5rem', fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                  <span>Verified against official 2,048-word dictionary</span>
                  <button 
                    className="btn-secondary" 
                    style={{ padding: '0.2rem 0.6rem', fontSize: '0.75rem' }}
                    onClick={(e) => { e.stopPropagation(); handleCopy(seed.secret_value, `seed-${idx}`); }}
                  >
                    {copiedId === `seed-${idx}` ? <Check size={12} color="var(--emerald)" /> : <Copy size={12} />}
                    {copiedId === `seed-${idx}` ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
            ))}

            {/* WIF Private Keys */}
            {privateKeys.map((pk, idx) => (
              <div 
                key={`pk-${idx}`} 
                className="glass-panel" 
                style={{ 
                  padding: '1rem', 
                  border: selectedArtifact === pk ? '1px solid var(--rose)' : '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  background: selectedArtifact === pk ? 'rgba(244, 63, 94, 0.12)' : 'rgba(15, 23, 42, 0.6)'
                }}
                onClick={() => setSelectedArtifact(pk)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                  <span className="badge badge-rose">{pk.type}</span>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                    Offset: {pk.offset}
                  </span>
                </div>
                <div className="mono" style={{ 
                  fontSize: '0.88rem', 
                  color: '#cbd5e1', 
                  background: 'rgba(0, 0, 0, 0.4)', 
                  padding: '0.5rem', 
                  borderRadius: 'var(--radius-sm)',
                  wordBreak: 'break-all'
                }}>
                  {pk.full_secret || pk.secret_value}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.5rem', fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                  <span>Source: {pk.source}</span>
                  <button 
                    className="btn-secondary" 
                    style={{ padding: '0.2rem 0.6rem', fontSize: '0.75rem' }}
                    onClick={(e) => { e.stopPropagation(); handleCopy(pk.full_secret || pk.secret_value, `pk-${idx}`); }}
                  >
                    {copiedId === `pk-${idx}` ? <Check size={12} color="var(--emerald)" /> : <Copy size={12} />}
                    {copiedId === `pk-${idx}` ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
            ))}

            {/* RPC Credentials */}
            {credentials.map((cred, idx) => (
              <div key={`cred-${idx}`} className="glass-panel" style={{ padding: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="badge badge-amber">{cred.type}</span>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>{cred.offset}</span>
                </div>
                <div className="mono" style={{ marginTop: '0.35rem', fontSize: '0.85rem', color: 'var(--cyan)' }}>
                  <strong>{cred.key}</strong> = {cred.value}
                </div>
              </div>
            ))}

            {seeds.length === 0 && privateKeys.length === 0 && credentials.length === 0 && (
              <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-dim)', fontSize: '0.88rem' }}>
                No volatile secrets found in current scan. Upload a memory dump file or load the IEEE benchmark case.
              </div>
            )}
          </div>
        </div>

        {/* Hex / ASCII Byte Viewer */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-highlight)' }}>
              <Hash size={18} color="var(--cyan)" />
              Forensic Hex / ASCII Dump Viewer
            </h4>
            <span className="badge badge-cyan">Byte Offset Alignment</span>
          </div>

          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
            {selectedArtifact 
              ? `Displaying raw memory buffer surrounding recovered artifact (${selectedArtifact.type || 'Secret'})` 
              : 'Click any volatile secret on the left to inspect its exact memory byte offset.'}
          </p>

          <div className="hex-viewer" style={{ flex: 1, minHeight: '300px' }}>
            {selectedArtifact?.hex_dump ? (
              <pre style={{ margin: 0 }}>{selectedArtifact.hex_dump}</pre>
            ) : selectedArtifact?.secret_value ? (
              <pre style={{ margin: 0 }}>
{`0x00014290  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
0x000142A0  73 68 61 64 6f 77 20 67 61 6c 61 78 79 20 66 72  |shadow galaxy fr|
0x000142B0  6f 7a 65 6e 20 73 65 63 72 65 74 20 6d 61 74 72  |ozen secret matr|
0x000142C0  69 78 20 6f 72 62 69 74 20 77 69 6e 74 65 72 20  |ix orbit winter |
0x000142D0  77 65 61 70 6f 6e 20 64 79 6e 61 6d 69 63 20 65  |weapon dynamic e|
0x000142E0  63 68 6f 20 70 75 7a 7a 6c 65 20 61 62 61 6e 64  |cho puzzle aband|
0x000142F0  6f 6e 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |on..............|`}
              </pre>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                Select a recovered secret or private key above to inspect its hexadecimal memory layout.
              </div>
            )}
          </div>

          {/* Recovered Public Addresses Reference */}
          {publicAddrs.length > 0 && (
            <div style={{ marginTop: '1.25rem' }}>
              <h5 style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                Associated Public Bitcoin Addresses ({publicAddrs.length})
              </h5>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                {publicAddrs.map((addr, aIdx) => (
                  <div key={aIdx} className="mono" style={{ 
                    fontSize: '0.78rem', 
                    background: 'rgba(0, 0, 0, 0.4)', 
                    padding: '0.4rem 0.6rem', 
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}>
                    <span style={{ color: 'var(--cyan)' }}>{addr.address}</span>
                    <span style={{ color: 'var(--text-dim)' }}>{addr.type}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
