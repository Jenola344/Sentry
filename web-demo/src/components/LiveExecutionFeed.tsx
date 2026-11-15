import React, { useState, useEffect, useRef } from 'react';
import { TelemetryLog } from '../engine/scanner';
import { Terminal, Shield, Cpu, ChevronRight, Copy, Check } from 'lucide-react';

interface Props {
  logs: TelemetryLog[];
  isScanning: boolean;
  onClearLogs: () => void;
}

export const LiveExecutionFeed: React.FC<Props> = ({ logs, isScanning, onClearLogs }) => {
  const [activeTab, setActiveTab] = useState<'LOGS' | 'COMMANDS' | 'SKILL'>('LOGS');
  const [copied, setCopied] = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const skillSnippet = `---
name: sentry
description: Zero-egress, 100% local security auditor for UGREEN AI NAS (UGOS). Scans shared storage for leaked API keys, crypto seed phrases, unencrypted PII, and financial records using native UGOS CLI tools (ug-filesystem, ug-filemgr, ug-document, ug-photo, ug-knowledge). Calculates context-aware risk scores, enforces strict zero-leak evidence masking, generates an interactive Risk Heatmap Report, and executes non-destructive, reversible quarantine strictly upon explicit human confirmation.
---`;

  const copySkill = () => {
    navigator.clipboard.writeText(skillSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="glass-panel rounded-2xl flex flex-col h-full border border-teal-500/20 shadow-2xl overflow-hidden font-mono">
      {/* Header Tabs */}
      <div className="p-3 bg-slate-950/80 border-b border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-xs">
          <button
            onClick={() => setActiveTab('LOGS')}
            className={`px-3 py-1.5 rounded-lg transition text-[11px] font-bold tracking-wider uppercase flex items-center gap-1.5 ${
              activeTab === 'LOGS'
                ? 'bg-teal-950 text-teal-300 border border-teal-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5 text-teal-400" />
            <span>Terminal ({logs.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('COMMANDS')}
            className={`px-3 py-1.5 rounded-lg transition text-[11px] font-bold tracking-wider uppercase flex items-center gap-1.5 ${
              activeTab === 'COMMANDS'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>UGOS CLI</span>
          </button>

          <button
            onClick={() => setActiveTab('SKILL')}
            className={`px-3 py-1.5 rounded-lg transition text-[11px] font-bold tracking-wider uppercase flex items-center gap-1.5 ${
              activeTab === 'SKILL'
                ? 'bg-teal-950 text-teal-300 border border-teal-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield className="w-3.5 h-3.5 text-teal-400" />
            <span>SKILL.md</span>
          </button>
        </div>

        {activeTab === 'LOGS' && logs.length > 0 && (
          <button
            onClick={onClearLogs}
            className="text-[10px] text-slate-500 hover:text-slate-300 transition"
          >
            Clear
          </button>
        )}
      </div>

      {/* Body Views */}
      <div className="p-4 flex-1 overflow-y-auto text-xs bg-slate-950/60 leading-relaxed min-h-[380px] max-h-[520px]">
        {activeTab === 'LOGS' && (
          <div className="space-y-2">
            {logs.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-600 py-20 text-center font-sans">
                <Terminal className="w-8 h-8 text-slate-700 mb-2" />
                <span className="text-xs">Execution feed idle.</span>
                <span className="text-[11px] text-slate-600 mt-1">
                  Click &quot;▶ Run Autonomous Demo&quot; or start an audit to stream live logs.
                </span>
              </div>
            ) : (
              logs.map((log) => {
                const isCrit = log.level === 'CRIT';
                const isWarn = log.level === 'WARN';
                const isAction = log.level === 'ACTION';

                return (
                  <div
                    key={log.id}
                    className={`p-2 rounded border text-[11px] transition ${
                      isCrit
                        ? 'bg-rose-950/30 border-rose-600/40 text-rose-300'
                        : isWarn
                        ? 'bg-amber-950/30 border-amber-600/40 text-amber-300'
                        : isAction
                        ? 'bg-teal-950/40 border-teal-500/50 text-teal-300 font-bold'
                        : 'bg-slate-900/40 border-slate-800 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 text-[10px] opacity-75">
                      <span className="text-slate-400">{log.timestamp}</span>
                      <span className="font-bold uppercase tracking-wider">
                        Pass {log.pass} • {log.level}
                      </span>
                    </div>
                    <div className="mt-1 font-semibold">{log.message}</div>
                    {log.detail && (
                      <div className="text-[10px] text-slate-400 mt-0.5 opacity-90 pl-2 border-l border-slate-700">
                        {log.detail}
                      </div>
                    )}
                  </div>
                );
              })
            )}
            <div ref={logEndRef} />
          </div>
        )}

        {activeTab === 'COMMANDS' && (
          <div className="space-y-3 text-[11px]">
            <div className="text-[11px] text-slate-400 mb-2 font-sans">
              Native UGOS CLI system calls executed locally by Sentry:
            </div>

            <div className="p-2.5 rounded bg-slate-900/70 border border-slate-800">
              <div className="text-cyan-400 font-bold flex items-center gap-1.5">
                <ChevronRight className="w-3.5 h-3.5" />
                1. ug-filesystem
              </div>
              <code className="text-slate-300 text-[10px] block mt-1 break-all">
                ug-filesystem list --path &quot;/volume1/Shared&quot; --recursive --format json
              </code>
            </div>

            <div className="p-2.5 rounded bg-slate-900/70 border border-slate-800">
              <div className="text-cyan-400 font-bold flex items-center gap-1.5">
                <ChevronRight className="w-3.5 h-3.5" />
                2. ug-document
              </div>
              <code className="text-slate-300 text-[10px] block mt-1 break-all">
                ug-document extract --path &quot;/volume1/Shared/Projects/app1/.env&quot; --max-bytes 52428800
              </code>
            </div>

            <div className="p-2.5 rounded bg-slate-900/70 border border-slate-800">
              <div className="text-cyan-400 font-bold flex items-center gap-1.5">
                <ChevronRight className="w-3.5 h-3.5" />
                3. ug-photo (NPU Vision)
              </div>
              <code className="text-slate-300 text-[10px] block mt-1 break-all">
                ug-photo ocr --path &quot;/volume1/Shared/Photos/card_scan.png&quot; --lang eng --format json
              </code>
            </div>

            <div className="p-2.5 rounded bg-slate-900/70 border border-slate-800">
              <div className="text-cyan-400 font-bold flex items-center gap-1.5">
                <ChevronRight className="w-3.5 h-3.5" />
                4. ug-filemgr (Quarantine Move)
              </div>
              <code className="text-slate-300 text-[10px] block mt-1 break-all">
                ug-filemgr move --source &quot;/volume1/Shared/...&quot; --dest &quot;/volume1/Private_Security_Vault/...&quot; --create-parents
              </code>
            </div>

            <div className="p-2.5 rounded bg-slate-900/70 border border-slate-800">
              <div className="text-cyan-400 font-bold flex items-center gap-1.5">
                <ChevronRight className="w-3.5 h-3.5" />
                5. ug-knowledge
              </div>
              <code className="text-slate-300 text-[10px] block mt-1 break-all">
                ug-knowledge store --collection sentry_reports --doc &quot;Risk_Heatmap_Report.md&quot;
              </code>
            </div>
          </div>
        )}

        {activeTab === 'SKILL' && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] text-slate-400 font-sans">
                Official Uliya Skill Specification:
              </span>
              <button
                onClick={copySkill}
                className="text-[10px] bg-slate-800 hover:bg-slate-700 text-teal-400 px-2 py-1 rounded flex items-center gap-1"
              >
                {copied ? <Check className="w-3 h-3 text-teal-400" /> : <Copy className="w-3 h-3" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-[10px] text-teal-300/90 leading-normal overflow-x-auto whitespace-pre-wrap">
              {skillSnippet}
            </pre>
          </div>
        )}
      </div>

      {/* Footer Status */}
      <div className="p-2.5 bg-slate-950 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500">
        <span className="flex items-center gap-1.5">
          <span className={`w-1.5 h-1.5 rounded-full ${isScanning ? 'bg-cyan-400 animate-ping' : 'bg-teal-400'}`}></span>
          {isScanning ? 'Streaming Telemetry...' : 'Daemon In Standby'}
        </span>
        <span>SHA-256 Verified</span>
      </div>
    </div>
  );
};
