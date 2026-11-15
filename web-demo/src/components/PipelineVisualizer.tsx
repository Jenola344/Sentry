import React from 'react';
import { ScanStats } from '../engine/scanner';
import {
  HardDrive,
  FileCode2,
  FileSpreadsheet,
  Image as ImageIcon,
  CheckCircle2,
  Loader2,
  Users,
  Globe2,
  Zap,
  Layers
} from 'lucide-react';

interface Props {
  stats: ScanStats;
  isShared: boolean;
  isPublic: boolean;
  scanDepth: 'quick' | 'standard' | 'deep';
  onToggleShared: (val: boolean) => void;
  onTogglePublic: (val: boolean) => void;
  onChangeDepth: (depth: 'quick' | 'standard' | 'deep') => void;
}

export const PipelineVisualizer: React.FC<Props> = ({
  stats,
  isShared,
  isPublic,
  scanDepth,
  onToggleShared,
  onTogglePublic,
  onChangeDepth
}) => {
  const nodes = [
    {
      id: 1,
      title: '01. SCOPE & INVENTORY',
      binary: 'ug-filesystem',
      icon: HardDrive,
      summary: '50MB Budget • Lockfile Whitelist',
      status: stats.currentPass === 1 && stats.isScanning ? 'active' : stats.currentPass > 1 || stats.isDone ? 'done' : 'idle'
    },
    {
      id: 2,
      title: '02. TEXT & CODE SECRETS',
      binary: 'ug-document',
      icon: FileCode2,
      summary: 'API Keys • BIP-39 • DB URIs',
      status: stats.currentPass === 2 && stats.isScanning ? 'active' : stats.currentPass > 2 || stats.isDone ? 'done' : 'idle'
    },
    {
      id: 3,
      title: '03. STRUCTURED DOCS & PII',
      binary: 'ug-document',
      icon: FileSpreadsheet,
      summary: 'Payroll • SSN • IBAN Accounts',
      status: scanDepth === 'quick' ? 'skipped' : stats.currentPass === 3 && stats.isScanning ? 'active' : stats.currentPass > 3 || stats.isDone ? 'done' : 'idle'
    },
    {
      id: 4,
      title: '04. IMAGE TEXT & METADATA',
      binary: 'ug-photo',
      icon: ImageIcon,
      summary: 'Embedded Text • EXIF • Luhn',
      status: scanDepth !== 'deep' ? 'skipped' : stats.currentPass === 4 && stats.isScanning ? 'active' : stats.isDone ? 'done' : 'idle'
    }
  ];

  return (
    <div className="glass-panel rounded-2xl p-5 shadow-2xl relative overflow-hidden border border-teal-500/25">
      {/* Background Animated Laser Scan Line during active scan */}
      {stats.isScanning && (
        <div className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent laser-beam-anim pointer-events-none z-10 opacity-70"></div>
      )}

      {/* Top Header & Settings Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-teal-950/80 border border-teal-500/40 flex items-center justify-center text-teal-400">
            <Zap className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-mono font-bold text-white tracking-wide flex items-center gap-2">
              FOUR-PASS DETERMINISTIC PIPELINE
              <span className="text-[10px] text-teal-400 bg-teal-950/80 border border-teal-500/30 px-2 py-0.5 rounded font-mono">
                LOCAL UGOS DAEMON
              </span>
            </h3>
            <p className="text-[11px] font-mono text-slate-400 mt-0.5">
              Deterministic file routing with Intel AI Boost NPU hardware acceleration.
            </p>
          </div>
        </div>

        {/* Share Exposure Context Toggles */}
        <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-2 bg-slate-950/80 border border-slate-800 px-3 py-1.5 rounded-xl">
            <span className="text-slate-500 text-[11px]">Context:</span>
            
            {/* Multi-user toggle */}
            <button
              onClick={() => onToggleShared(!isShared)}
              disabled={stats.isScanning}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg transition text-[11px] font-semibold ${
                isShared
                  ? 'bg-teal-950 text-teal-300 border border-teal-500/50 shadow-sm'
                  : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              <Users className="w-3 h-3" />
              <span>Multi-User (+0.50)</span>
            </button>

            {/* Public/Guest toggle */}
            <button
              onClick={() => onTogglePublic(!isPublic)}
              disabled={stats.isScanning}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg transition text-[11px] font-semibold ${
                isPublic
                  ? 'bg-amber-950 text-amber-300 border border-amber-500/50 shadow-sm'
                  : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              <Globe2 className="w-3 h-3" />
              <span>Public Guest (+0.75)</span>
            </button>
          </div>

          {/* Depth Selector */}
          <div className="flex items-center gap-2 bg-slate-950/80 border border-slate-800 px-3 py-1.5 rounded-xl">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <select
              value={scanDepth}
              onChange={(e) => onChangeDepth(e.target.value as any)}
              disabled={stats.isScanning}
              className="bg-transparent text-slate-200 text-[11px] font-mono focus:outline-none cursor-pointer"
            >
              <option value="quick" className="bg-slate-900">Depth: Quick (Pass 1-2)</option>
              <option value="standard" className="bg-slate-900">Depth: Standard (Pass 1-3)</option>
              <option value="deep" className="bg-slate-900">Depth: Deep (Image text)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Connected Neural Pipeline Nodes */}
      <div className="mt-5 relative">
        {/* SVG Connector Lines Behind Nodes */}
        <div className="hidden lg:block absolute top-1/2 left-8 right-8 -translate-y-1/2 h-0.5 bg-slate-800 -z-0">
          <div
            className="h-full bg-gradient-to-r from-teal-500 via-cyan-400 to-teal-400 transition-all duration-500"
            style={{
              width: stats.isDone
                ? '100%'
                : stats.currentPass === 1
                ? '25%'
                : stats.currentPass === 2
                ? '50%'
                : stats.currentPass === 3
                ? '75%'
                : '100%'
            }}
          ></div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 relative z-10">
          {nodes.map((n) => {
            const Icon = n.icon;
            const isActive = n.status === 'active';
            const isDone = n.status === 'done';
            const isSkipped = n.status === 'skipped';

            return (
              <div
                key={n.id}
                className={`p-3.5 rounded-xl border transition-all duration-300 font-mono ${
                  isActive
                    ? 'bg-slate-900/90 border-teal-400 shadow-lg shadow-teal-500/20 scale-[1.02]'
                    : isDone
                    ? 'bg-slate-950/80 border-teal-500/30'
                    : isSkipped
                    ? 'bg-slate-950/40 border-slate-900 opacity-40'
                    : 'bg-slate-950/60 border-slate-800/80 opacity-70'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <div
                      className={`w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold ${
                        isActive
                          ? 'bg-teal-500 text-slate-950'
                          : isDone
                          ? 'bg-slate-800 text-teal-400 border border-teal-500/30'
                          : 'bg-slate-900 text-slate-500 border border-slate-800'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                    </div>
                    <span className="text-[10px] text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                      {n.binary}
                    </span>
                  </div>

                  <div>
                    {isActive && <Loader2 className="w-4 h-4 text-teal-400 animate-spin" />}
                    {isDone && <CheckCircle2 className="w-4 h-4 text-teal-400" />}
                    {isSkipped && <span className="text-[9px] text-slate-600 uppercase">Bypassed</span>}
                  </div>
                </div>

                <div className="text-xs font-bold text-slate-200 tracking-tight">{n.title}</div>
                <div className="text-[10px] text-slate-400 mt-1">{n.summary}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Inspection Ticker Bar */}
      <div className="mt-4 pt-3 border-t border-slate-800/60 flex flex-wrap items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2 truncate max-w-xl">
          <span className="text-slate-500 uppercase text-[10px]">Scanning Node:</span>
          <span className="text-cyan-300 font-bold truncate">
            {stats.currentFile || 'Ready to execute audit.'}
          </span>
        </div>

        <div className="flex items-center gap-3 text-[11px] text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-teal-400"></span>
            Pass 1-4 Bound to Hardware
          </span>
        </div>
      </div>
    </div>
  );
};
