import React, { useState } from 'react';
import { BookOpen, Copy, Check, Terminal, Cpu, Shield, X } from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export const ArchitectureModal: React.FC<Props> = ({ isOpen, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const skillSnippet = `---
name: sentry
description: Zero-egress, 100% local security auditor for UGREEN AI NAS (UGOS). Scans shared storage for leaked API keys, crypto seed phrases, unencrypted PII, and financial records using native UGOS CLI tools (ug-filesystem, ug-filemgr, ug-document, ug-photo, ug-knowledge). Calculates context-aware risk scores, enforces strict zero-leak evidence masking, generates an interactive Risk Heatmap Report, and executes non-destructive, reversible quarantine strictly upon explicit human confirmation.
---`;

  const copyToClipboard = () => {
    navigator.clipboard.writeText(skillSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const ugosCommands = [
    { cmd: 'ug-filesystem', domain: 'Storage Enumeration', desc: 'Queries mount points, POSIX bitmasks, and network sharing context (SMB/NFS/WebDAV).' },
    { cmd: 'ug-document', domain: 'Text & Doc Parsing', desc: 'Streams plain text from code, .env, PDFs, Word docs, and CSVs up to 50MB budget.' },
    { cmd: 'ug-photo', domain: 'NPU-Accelerated OCR', desc: 'Dispatches image files to Intel AI Boost NPU for visual layout and card text detection.' },
    { cmd: 'ug-knowledge', domain: 'Local Report Indexing', desc: 'Persists Risk Heatmap Reports locally into semantic memory without cloud telemetry.' },
    { cmd: 'ug-filemgr', domain: 'Atomic Isolation & Rollback', desc: 'Executes directory-preserving non-destructive moves and 1-click restoration.' }
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-950/80 border border-emerald-500/50 flex items-center justify-center text-emerald-400">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                UGREEN Uliya Skill Standard & Native UGOS Orchestration
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Declarative Markdown Skill architecture running 100% on the UGREEN AI NAS iDX6011 Pro.
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200 transition p-1">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs font-sans">
          {/* SKILL.md Frontmatter Box */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                <BookOpen className="w-4 h-4 text-emerald-400" />
                skill/sentry/SKILL.md Frontmatter (YAML)
              </span>
              <button
                onClick={copyToClipboard}
                className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded flex items-center gap-1 transition"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-[11px] text-emerald-300/90 overflow-x-auto whitespace-pre-wrap">
              {skillSnippet}
            </pre>
          </div>

          {/* Native UGOS Commands Table */}
          <div>
            <h4 className="font-semibold text-slate-300 flex items-center gap-1.5 mb-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Native UGOS CLI Commands Orchestrated by Sentry
            </h4>
            <div className="border border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-800">
              {ugosCommands.map((item) => (
                <div key={item.cmd} className="p-3 bg-slate-950/40 flex items-start justify-between gap-4">
                  <div>
                    <code className="text-emerald-400 font-mono font-bold text-xs">{item.cmd}</code>
                    <div className="text-slate-400 text-[11px] mt-0.5">{item.desc}</div>
                  </div>
                  <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-medium whitespace-nowrap">
                    {item.domain}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Zero Egress Guarantee */}
          <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-4 flex items-center gap-3">
            <Shield className="w-8 h-8 text-emerald-400 shrink-0" />
            <div>
              <div className="font-semibold text-slate-200">100% Zero-Egress Guarantee</div>
              <p className="text-slate-400 text-[11px] mt-0.5">
                Sentry instantiates no network sockets, contacts no remote servers, and requires no third-party cloud models. All evaluations run strictly on the NAS internal bus and NPU.
              </p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition text-xs font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
