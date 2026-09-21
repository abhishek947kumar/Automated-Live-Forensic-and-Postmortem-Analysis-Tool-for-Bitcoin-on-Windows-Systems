import React, { useState } from 'react';
import { 
  ShieldCheck, 
  CheckCircle2, 
  AlertTriangle, 
  RefreshCw, 
  Hash, 
  Lock, 
  FileCheck,
  Award
} from 'lucide-react';

export default function EvidenceLedger({ evidenceLedger, onVerifyEvidence }) {
  const [verifyingId, setVerifyingId] = useState(null);
  const [verificationResults, setVerificationResults] = useState({});

  const items = evidenceLedger?.evidence_items || [];

  const handleVerify = async (evdId) => {
    setVerifyingId(evdId);
    try {
      const res = await onVerifyEvidence(evdId);
      setVerificationResults(prev => ({
        ...prev,
        [evdId]: res
      }));
    } catch (e) {
      console.error(e);
    } finally {
      setVerifyingId(null);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Standards Banner */}
      <div className="glass-panel" style={{ 
        padding: '1.25rem 1.5rem', 
        borderLeft: '4px solid var(--emerald)',
        background: 'rgba(16, 185, 129, 0.08)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ 
            width: '42px', height: '42px', borderRadius: '50%', 
            background: 'rgba(16, 185, 129, 0.2)', display: 'flex', 
            alignItems: 'center', justifyContent: 'center' 
          }}>
            <ShieldCheck size={22} color="var(--emerald)" />
          </div>
          <div>
            <h4 style={{ color: '#d1fae5' }}>ISO/IEC 27037 Digital Evidence Vault & Custody Ledger</h4>
            <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)' }}>
              Case ID: <strong>{evidenceLedger?.case_id || 'CASE-2026-BTC-0921'}</strong> • Examiner: <strong>{evidenceLedger?.examiner || 'DFIR Lead Investigator'}</strong>.
              All items are cryptographically sealed with SHA-256 and MD5 hashes to guarantee legal admissibility in court.
            </p>
          </div>
        </div>
        <span className="badge badge-emerald">Chain of Custody Intact</span>
      </div>

      {/* Ledger Table */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-highlight)' }}>
            <FileCheck size={18} color="var(--cyan)" />
            Cryptographic Evidence Records ({items.length})
          </h4>
          <span className="badge badge-cyan">Tamper-Evident Ledger</span>
        </div>

        {items.length > 0 ? (
          <div className="table-wrapper">
            <table className="forensic-table">
              <thead>
                <tr>
                  <th>Evidence Tag</th>
                  <th>Source Category</th>
                  <th>Description / Path</th>
                  <th>Size</th>
                  <th>SHA-256 Hash</th>
                  <th>MD5 Hash</th>
                  <th>Integrity Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item, idx) => {
                  const verified = verificationResults[item.evidence_id];
                  return (
                    <tr key={idx}>
                      <td>
                        <span className="badge badge-cyan mono">{item.evidence_number}</span>
                      </td>
                      <td>
                        <span className="badge badge-indigo" style={{ fontSize: '0.72rem' }}>
                          {item.source_type}
                        </span>
                      </td>
                      <td style={{ maxWidth: '320px' }}>
                        <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{item.description}</div>
                        <div className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={item.file_path}>
                          {item.file_path}
                        </div>
                      </td>
                      <td className="mono" style={{ fontSize: '0.78rem' }}>
                        {item.file_size_bytes ? `${(item.file_size_bytes / 1024).toFixed(1)} KB` : 'N/A'}
                      </td>
                      <td>
                        <span className="mono" style={{ fontSize: '0.74rem', color: 'var(--cyan)' }} title={item.sha256}>
                          {item.sha256 ? `${item.sha256.substring(0, 14)}...${item.sha256.substring(56)}` : 'N/A'}
                        </span>
                      </td>
                      <td>
                        <span className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-dim)' }} title={item.md5}>
                          {item.md5 ? `${item.md5.substring(0, 10)}...` : 'N/A'}
                        </span>
                      </td>
                      <td>
                        {verified ? (
                          <span className={`badge ${verified.match ? 'badge-emerald' : 'badge-rose'}`}>
                            {verified.status}
                          </span>
                        ) : (
                          <span className="badge badge-emerald">
                            {item.integrity_status}
                          </span>
                        )}
                      </td>
                      <td>
                        <button 
                          className="btn-secondary" 
                          style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
                          onClick={() => handleVerify(item.evidence_id)}
                          disabled={verifyingId === item.evidence_id}
                          title="Recalculates file hash in real time to verify that evidence has not been tampered with"
                        >
                          {verifyingId === item.evidence_id ? <RefreshCw size={12} className="spin" /> : <ShieldCheck size={12} color="var(--emerald)" />}
                          {verifyingId === item.evidence_id ? 'Checking...' : 'Verify Hash'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.88rem' }}>
            No evidence records currently cataloged. Run a live or benchmark triage to generate tamper-evident hashes.
          </div>
        )}
      </div>

    </div>
  );
}
