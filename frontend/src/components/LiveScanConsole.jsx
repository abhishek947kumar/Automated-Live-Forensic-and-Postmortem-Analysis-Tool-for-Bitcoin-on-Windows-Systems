import React, { useEffect, useRef } from 'react';
import { Terminal, Shield, CheckCircle2 } from 'lucide-react';

export default function LiveScanConsole({ logs, isActive }) {
  const consoleEndRef = useRef(null);

  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="glass-panel" style={{ padding: '1.25rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
        <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-highlight)', fontSize: '0.92rem' }}>
          <Terminal size={16} color="var(--cyan)" />
          Live Forensic Acquisition Stream (ISO/IEC 27037 Telemetry)
        </h4>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span className="dot" style={{ background: isActive ? 'var(--cyan)' : 'var(--emerald)' }}></span>
          <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
            {isActive ? 'ACQUIRING...' : 'IDLE / READY'}
          </span>
        </div>
      </div>

      <div className="live-console">
        {logs.map((log, idx) => (
          <div key={idx} className="log-entry">
            <span className="log-ts">[{log.timestamp}]</span>
            <span className="log-phase">[{log.phase}]</span>
            <span className="log-msg">{log.message}</span>
          </div>
        ))}
        {logs.length === 0 && (
          <div style={{ color: 'var(--text-dim)', fontStyle: 'italic', padding: '1rem', textAlign: 'center' }}>
            Forensic engine initialized. Execute Live Triage or load the IEEE Benchmark case to observe acquisition telemetry.
          </div>
        )}
        <div ref={consoleEndRef} />
      </div>
    </div>
  );
}
