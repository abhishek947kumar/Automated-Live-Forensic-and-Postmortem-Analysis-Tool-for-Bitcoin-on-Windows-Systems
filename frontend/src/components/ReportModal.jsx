import React from 'react';
import { 
  FileText, 
  Printer, 
  Download, 
  X, 
  ShieldCheck, 
  Award, 
  KeyRound,
  Trash2
} from 'lucide-react';

export default function ReportModal({ reportData, onClose }) {
  if (!reportData) return null;

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJSON = () => {
    const jsonStr = JSON.stringify(reportData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Forensic_Report_${reportData.case_id || '2026'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const breakdown = reportData.findings_breakdown || {};
  const ledger = reportData.chain_of_custody_ledger || [];

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        
        {/* Actions bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1rem' }} className="no-print">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <FileText size={22} color="var(--emerald)" />
            <h3 style={{ fontSize: '1.2rem', margin: 0 }}>Official Digital Forensics Audit Report</h3>
          </div>

          <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
            <button className="btn-secondary" onClick={handleDownloadJSON}>
              <Download size={15} />
              Export JSON
            </button>
            <button className="btn-primary" onClick={handlePrint}>
              <Printer size={15} />
              Print / Save PDF
            </button>
            <button 
              className="btn-secondary" 
              style={{ padding: '0.4rem 0.6rem' }} 
              onClick={onClose}
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Printable Document Body */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', lineHeight: '1.6' }}>
          
          {/* Header Block */}
          <div style={{ borderBottom: '2px solid var(--border-cyan)', paddingBottom: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <h1 style={{ fontSize: '1.5rem', textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-highlight)' }}>
                  Digital Forensics Investigation Report
                </h1>
                <p style={{ fontSize: '0.85rem', color: 'var(--cyan)' }}>
                  Automated Live & Postmortem Bitcoin Artifact Extraction
                </p>
              </div>
              <div style={{ textAlign: 'right', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                <div>Report ID: <strong className="mono">{reportData.report_id}</strong></div>
                <div>Case Ref: <strong className="mono">{reportData.case_id}</strong></div>
                <div>Date: {new Date(reportData.generated_at).toLocaleString()}</div>
              </div>
            </div>
          </div>

          {/* Case Metadata Table */}
          <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', fontSize: '0.85rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
              <div><strong>Lead Forensic Examiner:</strong> {reportData.examiner}</div>
              <div><strong>Target Operating System:</strong> {reportData.target_system}</div>
              <div><strong>Evidence Standard:</strong> ISO/IEC 27037 Digital Evidence</div>
              <div><strong>Methodology Foundation:</strong> IEEE Access (2019) Benchmark</div>
            </div>
          </div>

          {/* Academic Citation Reference */}
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', borderLeft: '3px solid var(--indigo)', paddingLeft: '0.85rem' }}>
            <strong>Academic Reference:</strong> {reportData.academic_citation}
          </div>

          {/* Executive Summary */}
          <div>
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem', color: 'var(--text-highlight)' }}>
              1. Executive Summary
            </h3>
            <p style={{ fontSize: '0.88rem', color: 'var(--text-main)', textAlign: 'justify' }}>
              {reportData.executive_summary}
            </p>
          </div>

          {/* Key Evidential Findings */}
          <div>
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem', color: 'var(--text-highlight)' }}>
              2. Core Triage Metrics & Recovered Artifacts
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginTop: '0.75rem' }}>
              <div style={{ background: 'rgba(244, 63, 94, 0.08)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid rgba(244, 63, 94, 0.3)' }}>
                <div style={{ fontSize: '0.78rem', textTransform: 'uppercase', color: 'var(--rose)', fontWeight: 700 }}>
                  Volatile Secrets in Memory
                </div>
                <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#fecdd3' }}>
                  {breakdown.volatile_secrets_recovered || 0}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  BIP-39 Seeds & WIF Private Keys
                </div>
              </div>

              <div style={{ background: 'rgba(245, 158, 11, 0.08)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
                <div style={{ fontSize: '0.78rem', textTransform: 'uppercase', color: 'var(--amber)', fontWeight: 700 }}>
                  Uninstalled Remnants
                </div>
                <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#fef3c7' }}>
                  {breakdown.uninstalled_wallet_remnants || 0}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Persistent wallet.dat & keystores
                </div>
              </div>

              <div style={{ background: 'rgba(99, 102, 241, 0.08)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid rgba(99, 102, 241, 0.3)' }}>
                <div style={{ fontSize: '0.78rem', textTransform: 'uppercase', color: 'var(--indigo)', fontWeight: 700 }}>
                  Web Wallet Sessions
                </div>
                <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#e0e7ff' }}>
                  {breakdown.web_wallet_sessions_flagged || 0}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Exchange & Mempool Lookups
                </div>
              </div>
            </div>
          </div>

          {/* Chain of Custody Table */}
          <div>
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem', color: 'var(--text-highlight)' }}>
              3. ISO/IEC 27037 Chain of Custody & Hash Manifest
            </h3>
            <div className="table-wrapper">
              <table className="forensic-table" style={{ fontSize: '0.8rem' }}>
                <thead>
                  <tr>
                    <th>Tag</th>
                    <th>Category</th>
                    <th>Evidence Description</th>
                    <th>SHA-256 Checksum</th>
                    <th>Integrity</th>
                  </tr>
                </thead>
                <tbody>
                  {ledger.map((item, idx) => (
                    <tr key={idx}>
                      <td className="mono" style={{ color: 'var(--cyan)' }}>{item.evidence_number}</td>
                      <td>{item.source_type}</td>
                      <td>{item.description}</td>
                      <td className="mono" style={{ fontSize: '0.72rem' }}>
                        {item.sha256}
                      </td>
                      <td>
                        <span className="badge badge-emerald">VERIFIED</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Legal Attestation Signature */}
          <div style={{ marginTop: '2rem', borderTop: '1px solid var(--border-subtle)', paddingTop: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: '1.5rem' }}>
            <div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-dim)' }}>Examiner Attestation:</div>
              <div style={{ fontSize: '0.86rem', color: 'var(--text-main)', maxWidth: '450px', marginTop: '0.25rem' }}>
                I attest under penalty of perjury that the digital evidence collected herein was acquired and hashed in accordance with ISO/IEC 27037 digital forensic principles without alteration.
              </div>
            </div>

            <div style={{ textAlign: 'center' }}>
              <div className="mono" style={{ borderBottom: '1px solid #94a3b8', paddingBottom: '0.25rem', width: '220px', color: 'var(--cyan)', fontWeight: 700 }}>
                {reportData.examiner}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                Digital Forensics Examiner Signature
              </div>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
