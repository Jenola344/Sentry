import React from 'react';
import {
  ShieldCheck,
  Cpu,
  WifiOff,
  Play,
  Upload,
  HardDrive,
  FileDown,
  Sparkles
} from 'lucide-react';

interface Props {
  onRunAutoDemo: () => void;
  onLoadSample: () => void;
  onFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onOpenArchitecture: () => void;
  onExportReport: () => void;
  isScanning: boolean;
  fileCount: number;
}

export const HeaderHUD: React.FC<Props> = ({
  onRunAutoDemo,
  onLoadSample,
  onFileUpload,
  onOpenArchitecture,
  onExportReport,
  isScanning,
  fileCount
}) => {
  return (
    <header className="border-b border-teal-500/20 bg-slate-950/80 backdrop-blur-xl sticky top-0 z-40 px-6 py-3.5 shadow-2xl">
      <div className="max-w-[1600px] mx-auto flex flex-wrap items-center justify-between gap-4">
        {/* Left: Brand & Telemetry Badge */}
        <div className="flex items-center gap-4">
          <div className="relative group cursor-pointer">
            <div className="absolute -inset-1 bg-gradient-to-r from-teal-500 to-cyan-500 rounded-xl blur-sm opacity-60 group-hover:opacity-100 transition duration-300"></div>
            <div className="relative w-10 h-10 rounded-xl bg-slate-950 border border-teal-400/40 flex items-center justify-center text-teal-400 shadow-inner">
              <ShieldCheck className="w-5 h-5 text-teal-400 animate-pulse" />
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2.5">
              <span className="font-extrabold text-base tracking-wider text-white font-mono uppercase">
                SENTRY
              </span>
              <span className="text-[10px] font-mono font-bold tracking-widest uppercase bg-teal-950/70 text-teal-300 border border-teal-500/30 px-2 py-0.5 rounded">
                UGOS • ULIYA v1.0
              </span>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/40 border border-cyan-800/40 px-2 py-0.5 rounded hidden sm:inline-block">
                iDX6011 Pro NPU
              </span>
            </div>
            <div className="text-[11px] font-mono text-slate-400 flex items-center gap-2 mt-0.5">
              <span>ZERO-EGRESS AUTONOMOUS AUDITOR</span>
              <span className="text-slate-600">•</span>
              <span className="text-teal-400 font-semibold">AIR-GAPPED PROTOCOL</span>
            </div>
          </div>
        </div>

        {/* Center: Live Zero-Egress Network Shield Indicator */}
        <div className="flex items-center gap-3 bg-slate-900/80 border border-teal-500/25 px-4 py-1.5 rounded-full shadow-inner">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-teal-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-teal-500"></span>
            </span>
            <WifiOff className="w-3.5 h-3.5 text-teal-400" />
            <span className="text-[11px] font-mono font-bold tracking-wide text-teal-300 uppercase">
              0.00 KB EGRESS • AIR-GAPPED
            </span>
          </div>
          <span className="text-slate-700">|</span>
          <span className="text-[11px] font-mono text-slate-400">
            LOCAL BUS ONLY
          </span>
        </div>

        {/* Right: Command Actions & Hero CTA */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Hero Autonomous Demo CTA */}
          <button
            onClick={onRunAutoDemo}
            disabled={isScanning}
            className={`relative group px-4 py-2 rounded-xl text-xs font-mono font-bold tracking-wider uppercase transition overflow-hidden shadow-lg ${
              isScanning
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                : 'bg-gradient-to-r from-teal-600 to-cyan-600 text-slate-950 hover:from-teal-500 hover:to-cyan-500 shadow-teal-500/25 border border-teal-300'
            }`}
          >
            <div className="flex items-center gap-2 relative z-10 font-black">
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>▶ Run Autonomous Demo</span>
              <Sparkles className="w-3.5 h-3.5" />
            </div>
          </button>

          {/* Load Sample NAS Button */}
          <button
            onClick={onLoadSample}
            disabled={isScanning}
            className="text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white px-3 py-2 rounded-xl border border-slate-800 hover:border-teal-500/40 transition flex items-center gap-1.5"
            title="Load simulated UGREEN NAS volume with 11 test cases"
          >
            <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden md:inline">Mount NAS ({fileCount})</span>
          </button>

          {/* Ingest Local Files */}
          <label className="text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white px-3 py-2 rounded-xl border border-slate-800 hover:border-teal-500/40 transition flex items-center gap-1.5 cursor-pointer">
            <Upload className="w-3.5 h-3.5 text-teal-400" />
            <span className="hidden md:inline">Drop Files</span>
            <input type="file" multiple onChange={onFileUpload} className="hidden" />
          </label>

          {/* Export Report */}
          <button
            onClick={onExportReport}
            className="text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white px-3 py-2 rounded-xl border border-slate-800 hover:border-cyan-500/40 transition flex items-center gap-1.5"
            title="Download Risk Heatmap Report in Markdown"
          >
            <FileDown className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden lg:inline">Export Report</span>
          </button>

          {/* UGOS Architecture Modal Trigger */}
          <button
            onClick={onOpenArchitecture}
            className="text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white px-3 py-2 rounded-xl border border-slate-800 hover:border-teal-500/40 transition flex items-center gap-1.5"
          >
            <Cpu className="w-3.5 h-3.5 text-teal-400" />
            <span>UGOS Spec</span>
          </button>
        </div>
      </div>
    </header>
  );
};
