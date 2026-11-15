import React from 'react';
import { ScanStats } from '../engine/scanner';
import {
  FileText,
  ShieldAlert,
  Flame,
  Lock,
  Cpu,
  Activity
} from 'lucide-react';

interface Props {
  stats: ScanStats;
  maxScore: number;
  quarantinedCount: number;
  isShared: boolean;
  isPublic: boolean;
}

export const TelemetryStrip: React.FC<Props> = ({
  stats,
  maxScore,
  quarantinedCount,
  isShared,
  isPublic
}) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* 1. Files Audited */}
      <div className="glass-panel reticle-card rounded-xl p-4 transition-all hover:border-teal-400/50">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] font-mono tracking-wider font-semibold uppercase flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            Files Evaluated
          </span>
          <span className="text-[10px] font-mono bg-slate-900 border border-slate-800 text-slate-300 px-1.5 py-0.5 rounded">
            ug-filesystem
          </span>
        </div>

        <div className="mt-2 flex items-baseline justify-between">
          <div className="text-3xl font-mono font-black text-white tracking-tight">
            {stats.total}
          </div>
          <div className="text-[11px] font-mono text-slate-400">
            Pass {stats.currentPass}/4 Active
          </div>
        </div>

        {/* Mini Breakdown */}
        <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
          <span>Skipped: <strong className="text-slate-300">{stats.skippedMedia} media</strong></span>
          <span>Corrupt: <strong className="text-slate-300">{stats.skippedCorrupt}</strong></span>
          <span>Encrypted: <strong className="text-amber-400">{stats.unscannedEncrypted}</strong></span>
        </div>
      </div>

      {/* 2. Critical Exposures */}
      <div className={`glass-panel reticle-card rounded-xl p-4 transition-all ${
        stats.critical > 0
          ? 'border-rose-500/50 critical-pulse-glow bg-rose-950/20'
          : 'hover:border-teal-400/50'
      }`}>
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] font-mono tracking-wider font-semibold uppercase flex items-center gap-1.5">
            <ShieldAlert className={`w-3.5 h-3.5 ${stats.critical > 0 ? 'text-rose-400 animate-pulse' : 'text-slate-400'}`} />
            Critical Exposures
          </span>
          <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
            stats.critical > 0 ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-900 text-slate-500'
          }`}>
            S = 5.0
          </span>
        </div>

        <div className="mt-2 flex items-baseline justify-between">
          <div className={`text-3xl font-mono font-black tracking-tight ${
            stats.critical > 0 ? 'text-rose-400' : 'text-slate-300'
          }`}>
            {stats.critical}
          </div>
          <div className="text-[11px] font-mono text-rose-300/80">
            {stats.critical > 0 ? 'Urgent Lockdown' : 'Safe / Uncompromised'}
          </div>
        </div>

        <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
          <span>High Severity: <strong className="text-amber-300">{stats.high}</strong></span>
          <span>Medium: <strong className="text-teal-300">{stats.medium}</strong></span>
        </div>
      </div>

      {/* 3. Max Threat Score (R) */}
      <div className="glass-panel reticle-card rounded-xl p-4 transition-all hover:border-cyan-400/50">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] font-mono tracking-wider font-semibold uppercase flex items-center gap-1.5">
            <Flame className="w-3.5 h-3.5 text-amber-400" />
            Max Threat Score (R)
          </span>
          <span className="text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 px-1.5 py-0.5 rounded">
            R = S×(1+α+β)
          </span>
        </div>

        <div className="mt-2 flex items-baseline justify-between">
          <div className="text-3xl font-mono font-black text-amber-400 tracking-tight">
            {maxScore > 0 ? maxScore.toFixed(2) : '0.00'}
          </div>
          <div className="text-[11px] font-mono text-slate-400">
            Scale: 1.00 – 11.25
          </div>
        </div>

        <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
          <span>Multi-User: <strong className="text-teal-400">{isShared ? '+0.50' : '0.00'}</strong></span>
          <span>Public Guest: <strong className="text-teal-400">{isPublic ? '+0.75' : '0.00'}</strong></span>
        </div>
      </div>

      {/* 4. Isolated & Vaulted (Hardware Telemetry / Quarantine) */}
      <div className="glass-panel reticle-card rounded-xl p-4 transition-all hover:border-teal-400/50">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] font-mono tracking-wider font-semibold uppercase flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-teal-400" />
            Isolated & Vaulted
          </span>
          <span className="text-[10px] font-mono bg-teal-950 text-teal-300 border border-teal-800 px-1.5 py-0.5 rounded">
            ug-filemgr
          </span>
        </div>

        <div className="mt-2 flex items-baseline justify-between">
          <div className="text-3xl font-mono font-black text-teal-400 tracking-tight">
            {quarantinedCount}
          </div>
          <div className="text-[11px] font-mono text-teal-300">
            Reversible Ledger Ready
          </div>
        </div>

        {/* Live Hardware Meter */}
        <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
          <div className="flex items-center gap-1.5">
            <Cpu className="w-3 h-3 text-cyan-400" />
            <span>CPU: <strong className="text-slate-200">{stats.cpuLoad}%</strong></span>
          </div>
          <div className="flex items-center gap-1.5">
            <Activity className="w-3 h-3 text-teal-400" />
            <span>NPU: <strong className="text-teal-300">{stats.npuLoad}%</strong></span>
          </div>
        </div>
      </div>
    </div>
  );
};
