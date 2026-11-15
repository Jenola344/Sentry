import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
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

/** Value that rolls when it changes, so counters animate instead of snapping. */
const RollingNumber: React.FC<{ value: number; decimals?: number }> = ({ value, decimals = 0 }) => (
  <span className="digit-window">
    <AnimatePresence mode="popLayout" initial={false}>
      <motion.span
        key={`${value}`}
        initial={{ y: 16, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: -16, opacity: 0 }}
        transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
        className="inline-block"
      >
        {value.toFixed(decimals)}
      </motion.span>
    </AnimatePresence>
  </span>
);

export const TelemetryStrip: React.FC<Props> = ({
  stats,
  maxScore,
  quarantinedCount,
  isShared,
  isPublic
}) => {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {/* 1. Files Audited */}
      <div className="glass-panel reticle-card panel-lift sheen rounded-xl p-4">
        <div className="flex items-center justify-between gap-2 text-slate-400">
          <span className="flex min-w-0 items-center gap-1.5 text-[11px] font-mono font-semibold uppercase tracking-wider">
            <FileText className="w-3.5 h-3.5 shrink-0 text-cyan-400" />
            <span className="truncate">Files Evaluated</span>
          </span>
          <span className="shrink-0 whitespace-nowrap rounded border border-slate-800 bg-slate-900 px-1.5 py-0.5 font-mono text-[9px] text-slate-300">
            ug-filesystem
          </span>
        </div>

        <div className="mt-2 flex items-baseline justify-between">
          <div className="text-3xl font-mono font-black text-white tracking-tight">
            <RollingNumber value={stats.total} />
          </div>
          <div className="text-[11px] font-mono text-slate-400">
            Pass {stats.currentPass}/4 Active
          </div>
        </div>

        {/* Mini Breakdown */}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-slate-800/80 pt-2 font-mono text-[10px] text-slate-400">
          <span className="whitespace-nowrap">Skipped: <strong className="text-slate-300">{stats.skippedMedia} media</strong></span>
          <span className="whitespace-nowrap">Corrupt: <strong className="text-slate-300">{stats.skippedCorrupt}</strong></span>
          <span className="whitespace-nowrap">Encrypted: <strong className="text-amber-400">{stats.unscannedEncrypted}</strong></span>
        </div>
      </div>

      {/* 2. Critical Exposures */}
      <div className={`glass-panel reticle-card panel-lift rounded-xl p-4 ${
        stats.critical > 0
          ? 'border-rose-500/50 critical-pulse-glow bg-rose-950/20'
          : ''
      }`}>
        <div className="flex items-center justify-between gap-2 text-slate-400">
          <span className="flex min-w-0 items-center gap-1.5 text-[11px] font-mono font-semibold uppercase tracking-wider">
            <ShieldAlert className={`w-3.5 h-3.5 shrink-0 ${stats.critical > 0 ? 'text-rose-400 animate-pulse' : 'text-slate-400'}`} />
            <span className="truncate">Critical Exposures</span>
          </span>
          <span className={`shrink-0 whitespace-nowrap rounded px-1.5 py-0.5 font-mono text-[9px] ${
            stats.critical > 0 ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-900 text-slate-500'
          }`}>
            S = 5.0
          </span>
        </div>

        <div className="mt-2 flex items-baseline justify-between">
          <div className={`text-3xl font-mono font-black tracking-tight ${
            stats.critical > 0 ? 'text-rose-400' : 'text-slate-300'
          }`}>
            <RollingNumber value={stats.critical} />
          </div>
          <div className="whitespace-nowrap text-right font-mono text-[10px] leading-tight text-rose-300/80">
            {stats.critical > 0 ? 'Urgent lockdown' : 'No critical exposure'}
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-slate-800/80 pt-2 font-mono text-[10px] text-slate-400">
          <span className="whitespace-nowrap">High: <strong className="text-amber-300">{stats.high}</strong></span>
          <span className="whitespace-nowrap">Medium: <strong className="text-teal-300">{stats.medium}</strong></span>
        </div>
      </div>

      {/* 3. Max Threat Score (R) */}
      <div className="glass-panel reticle-card panel-lift sheen rounded-xl p-4">
        <div className="flex items-center justify-between gap-2 text-slate-400">
          <span className="flex min-w-0 items-center gap-1.5 text-[11px] font-mono font-semibold uppercase tracking-wider">
            <Flame className="w-3.5 h-3.5 shrink-0 text-amber-400" />
            <span className="truncate">Max Threat Score (R)</span>
          </span>
          <span className="shrink-0 whitespace-nowrap rounded border border-cyan-800 bg-cyan-950 px-1.5 py-0.5 font-mono text-[9px] text-cyan-300">
            R = S×(1+α+β)
          </span>
        </div>

        <div className="mt-2 flex items-baseline justify-between">
          <div className="text-3xl font-mono font-black text-amber-400 tracking-tight">
            <RollingNumber value={maxScore} decimals={2} />
          </div>
          <div className="whitespace-nowrap font-mono text-[10px] text-slate-400">
            Scale 1.00 – 11.25
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-slate-800/80 pt-2 font-mono text-[10px] text-slate-400">
          <span className="whitespace-nowrap">Multi-user: <strong className="text-teal-400">{isShared ? '+0.50' : '0.00'}</strong></span>
          <span className="whitespace-nowrap">Public: <strong className="text-teal-400">{isPublic ? '+0.75' : '0.00'}</strong></span>
        </div>
      </div>

      {/* 4. Isolated & Vaulted (Hardware Telemetry / Quarantine) */}
      <div className="glass-panel reticle-card panel-lift sheen rounded-xl p-4">
        <div className="flex items-center justify-between gap-2 text-slate-400">
          <span className="flex min-w-0 items-center gap-1.5 text-[11px] font-mono font-semibold uppercase tracking-wider">
            <Lock className="w-3.5 h-3.5 shrink-0 text-teal-400" />
            <span className="truncate">Isolated &amp; Vaulted</span>
          </span>
          <span className="shrink-0 whitespace-nowrap rounded border border-teal-800 bg-teal-950 px-1.5 py-0.5 font-mono text-[9px] text-teal-300">
            ug-filemgr
          </span>
        </div>

        <div className="mt-2 flex items-baseline justify-between">
          <div className="text-3xl font-mono font-black text-teal-400 tracking-tight">
            <RollingNumber value={quarantinedCount} />
          </div>
          <div className="whitespace-nowrap text-right font-mono text-[10px] leading-tight text-teal-300">
            Reversible ledger
          </div>
        </div>

        {/* Live Hardware Meter */}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-slate-800/80 pt-2 font-mono text-[10px] text-slate-400">
          <div className="flex items-center gap-1.5 whitespace-nowrap">
            <Cpu className="w-3 h-3 text-cyan-400" />
            <span>CPU <strong className="text-slate-200">{stats.cpuLoad}%</strong></span>
          </div>
          <div className="flex items-center gap-1.5 whitespace-nowrap">
            <Activity className="w-3 h-3 text-teal-400" />
            <span>NPU <strong className="text-teal-300">{stats.npuLoad}%</strong></span>
          </div>
        </div>
      </div>
    </div>
  );
};
