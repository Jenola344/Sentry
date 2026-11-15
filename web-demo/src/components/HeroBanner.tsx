import React from 'react';
import { motion } from 'framer-motion';
import { WifiOff, Fingerprint, Undo2, ShieldCheck } from 'lucide-react';

interface Props {
  fileCount: number;
  criticalCount: number;
  quarantinedCount: number;
  isScanning: boolean;
}

const pills = [
  { icon: WifiOff, label: '0 bytes egress' },
  { icon: Fingerprint, label: 'SHA-256 manifests' },
  { icon: Undo2, label: 'Reversible quarantine' },
  { icon: ShieldCheck, label: 'Human approval gate' }
];

export const HeroBanner: React.FC<Props> = ({
  fileCount,
  criticalCount,
  quarantinedCount,
  isScanning
}) => {
  return (
    <section className="relative overflow-hidden rounded-2xl border border-teal-500/15 bg-gradient-to-br from-slate-950/85 via-slate-950/45 to-teal-950/25 px-6 py-7 shadow-2xl">
      {/* Inner glow accents */}
      <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-teal-500/15 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-28 left-1/4 h-56 w-56 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="pointer-events-none absolute inset-x-6 top-0 h-px hairline opacity-70" />

      <div className="relative z-10 flex flex-wrap items-end justify-between gap-6">
        <div className="max-w-2xl">
          <div className="flex items-center gap-2 font-mono text-[10px] font-bold uppercase tracking-[0.32em] text-teal-300/85">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-teal-400 opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-teal-400" />
            </span>
            UGREEN AI NAS · iDX6011 Pro · UGOS
          </div>

          <h1 className="mt-3 text-3xl font-black leading-[1.08] tracking-tight text-white sm:text-4xl">
            Secrets rarely leak from the cloud.
            <br />
            <span className="text-gradient">They leak from your shared folders.</span>
          </h1>

          <p className="mt-3 max-w-xl text-sm leading-relaxed text-slate-400">
            Sentry reads every file on the appliance in four deterministic passes, scores
            exposure from real POSIX reachability, and quarantines only what you approve —
            with a checksum-backed rollback path.
          </p>

          <div className="mt-5 flex flex-wrap gap-2 font-mono text-[10px] uppercase tracking-wider">
            {pills.map(({ icon: Icon, label }) => (
              <span
                key={label}
                className="inline-flex items-center gap-1.5 rounded-full border border-teal-500/25 bg-slate-950/70 px-2.5 py-1 text-slate-300 transition hover:border-teal-400/50 hover:text-teal-200"
              >
                <Icon className="h-3 w-3 text-teal-400" />
                {label}
              </span>
            ))}
          </div>
        </div>

        {/* Live posture readout */}
        <div className="flex flex-wrap items-stretch gap-3 font-mono">
          <div className="rounded-xl border border-slate-800/90 bg-slate-950/70 px-4 py-3">
            <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Nodes mounted</div>
            <div className="mt-1 text-2xl font-black text-white">{fileCount}</div>
          </div>
          <div
            className={`rounded-xl border px-4 py-3 transition ${
              criticalCount > 0
                ? 'border-rose-500/45 bg-rose-950/25 shadow-lg shadow-rose-500/10'
                : 'border-slate-800/90 bg-slate-950/70'
            }`}
          >
            <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Critical</div>
            <div
              className={`mt-1 text-2xl font-black ${
                criticalCount > 0 ? 'text-rose-400' : 'text-slate-300'
              }`}
            >
              {criticalCount}
            </div>
          </div>
          <div className="rounded-xl border border-teal-500/25 bg-teal-950/25 px-4 py-3">
            <div className="text-[10px] uppercase tracking-[0.2em] text-teal-400/70">Vaulted</div>
            <div className="mt-1 text-2xl font-black text-teal-300">{quarantinedCount}</div>
          </div>

          <motion.div
            animate={
              isScanning
                ? { opacity: [0.55, 1, 0.55] }
                : { opacity: 1 }
            }
            transition={isScanning ? { duration: 1.8, repeat: Infinity } : { duration: 0.3 }}
            className="flex items-center gap-2 self-center rounded-xl border border-slate-800/90 bg-slate-950/70 px-3 py-2 text-[10px] uppercase tracking-[0.18em] text-slate-400"
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                isScanning ? 'bg-cyan-400' : 'bg-teal-400'
              }`}
            />
            {isScanning ? 'Auditing' : 'Standby'}
          </motion.div>
        </div>
      </div>
    </section>
  );
};
