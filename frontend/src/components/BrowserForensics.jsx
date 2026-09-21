import React from 'react';
import { 
  Globe, 
  Search, 
  ExternalLink, 
  Hash, 
  Clock, 
  Share2,
  ShieldCheck 
} from 'lucide-react';

export default function BrowserForensics({ browserData }) {
  const chromeUrls = browserData?.chrome || [];
  const edgeUrls = browserData?.edge || [];
  const ffUrls = browserData?.firefox || [];

  const allRecords = [...chromeUrls, ...edgeUrls, ...ffUrls];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Banner */}
      <div className="glass-panel" style={{ 
        padding: '1.25rem 1.5rem', 
        borderLeft: '4px solid var(--indigo)',
        background: 'rgba(99, 102, 241, 0.08)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ 
            width: '42px', height: '42px', borderRadius: '50%', 
            background: 'rgba(99, 102, 241, 0.2)', display: 'flex', 
            alignItems: 'center', justifyContent: 'center' 
          }}>
            <Globe size={22} color="var(--indigo)" />
          </div>
          <div>
            <h4 style={{ color: '#e0e7ff' }}>Web Wallet & Exchange Browser Forensics ({allRecords.length} Sessions)</h4>
            <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)' }}>
              Scans SQLite history databases across Chrome, Edge, and Firefox using forensic shadow copying to bypass live file locks.
              Extracts cryptocurrency exchange logins, blockchain explorer lookups, and transaction IDs.
            </p>
          </div>
        </div>
        <span className="badge badge-cyan">Section 6.3 Browser Evidence</span>
      </div>

      {/* History Records Table */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-highlight)' }}>
            <Search size={18} color="var(--cyan)" />
            Cryptocurrency Web Activity Log ({allRecords.length})
          </h4>
          <span className="badge badge-cyan">Browsers Triage</span>
        </div>

        {allRecords.length > 0 ? (
          <div className="table-wrapper">
            <table className="forensic-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Page Title & URL</th>
                  <th>Visit Count</th>
                  <th>Last Visited (UTC)</th>
                  <th>Extracted Identifiers (TXID / Addresses)</th>
                </tr>
              </thead>
              <tbody>
                {allRecords.map((item, idx) => (
                  <tr key={idx}>
                    <td>
                      <span className="badge badge-cyan" style={{ fontSize: '0.74rem' }}>
                        {item.matched_domain || 'Web Wallet'}
                      </span>
                    </td>
                    <td style={{ maxWidth: '480px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.2rem' }}>
                        {item.title || 'Cryptocurrency Web Session'}
                      </div>
                      <div className="mono" style={{ 
                        fontSize: '0.76rem', 
                        color: 'var(--text-dim)', 
                        overflow: 'hidden', 
                        textOverflow: 'ellipsis', 
                        whiteSpace: 'nowrap' 
                      }} title={item.url}>
                        {item.url}
                      </div>
                    </td>
                    <td>
                      <span className="badge badge-emerald">{item.visit_count} visits</span>
                    </td>
                    <td className="mono" style={{ fontSize: '0.78rem' }}>
                      {item.last_visit_time}
                    </td>
                    <td>
                      {item.extracted_txids && item.extracted_txids.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                          <span className="badge badge-rose" style={{ fontSize: '0.68rem' }}>
                            TXID Detected
                          </span>
                          <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--rose)' }}>
                            {item.extracted_txids[0].substring(0, 16)}...
                          </span>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-dim)', fontSize: '0.78rem' }}>Exchange Session</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.88rem' }}>
            No cryptocurrency web history detected in browser databases. Run the benchmark scan to review sample Coinbase and Blockchain.com visits.
          </div>
        )}
      </div>

    </div>
  );
}
