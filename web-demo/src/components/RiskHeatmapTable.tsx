import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Finding } from '../engine/scanner';
import { ScrambleSecret } from './ScrambleSecret';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  CheckSquare,
  Square,
  Lock,
  Search,
  Calculator,
  ChevronDown,
  ChevronUp
} from 'lucide-react';

interface Props {
  findings: Finding[];
  onToggleSelect: (id: string) => void;
  onSelectAllCritical: () => void;
  onSelectAll: () => void;
  onClearSelection: () => void;
  onOpenQuarantineModal: () => void;
  isShared: boolean;
  isPublic: boolean;
  quarantinedCount: number;
}

export const RiskHeatmapTable: React.FC<Props> = ({
  findings,
  onToggleSelect,
  onSelectAllCritical,
  onSelectAll,
  onClearSelection,
  onOpenQuarantineModal,
  isShared,
  isPublic,
  quarantinedCount
}) => {
  const [filter, setFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM'>('ALL');
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Dynamic sorting: Higher risk scores always float to the top
  const sortedFindings = [...findings].sort((a, b) => b.score_r - a.score_r);

  const filtered = sortedFindings.filter((f) => {
    if (filter !== 'ALL' && f.severity !== filter) return false;
    if (
      search &&
      !f.path.toLowerCase().includes(search.toLowerCase()) &&
      !f.category.toLowerCase().includes(search.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  const selectedCount = findings.filter((f) => f.selected).length;

  return (
    <div className="glass-panel rounded-2xl p-5 shadow-2xl border border-teal-500/20">
      {/* Control Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <h3 className="text-sm font-mono font-bold tracking-wide text-white uppercase flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-sm bg-teal-400 animate-pulse"></span>
              THREAT HEATMAP & FINDINGS MATRIX
            </h3>
            <span className="text-[10px] font-mono bg-slate-900 border border-slate-800 text-teal-300 px-2 py-0.5 rounded-full font-bold">
              {findings.length} THREATS IDENTIFIED
            </span>
            {quarantinedCount > 0 && (
              <span className="text-[10px] font-mono bg-teal-950 text-teal-300 border border-teal-500/40 px-2 py-0.5 rounded-full font-bold">
                {quarantinedCount} ISOLATED IN VAULT
              </span>
            )}
          </div>
          <p className="text-[11px] font-mono text-slate-400 mt-0.5">
            Real-time scoring <code className="text-teal-400 font-semibold">R = S × (1 + α[{isShared ? '0.50' : '0.00'}] + β[{isPublic ? '0.75' : '0.00'}])</code>.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2 font-mono">
          <button
            onClick={onSelectAllCritical}
            className="text-[11px] bg-rose-950/60 hover:bg-rose-900/60 border border-rose-500/40 text-rose-300 px-3 py-1.5 rounded-lg transition"
          >
            Select All Critical
          </button>
          <button
            onClick={onSelectAll}
            className="text-[11px] bg-slate-900 hover:bg-slate-800 text-slate-300 px-3 py-1.5 rounded-lg border border-slate-800 transition"
          >
            Select All
          </button>
          {selectedCount > 0 && (
            <button
              onClick={onClearSelection}
              className="text-[11px] text-slate-500 hover:text-slate-300 px-2 py-1 transition"
            >
              Clear
            </button>
          )}

          <button
            onClick={onOpenQuarantineModal}
            disabled={selectedCount === 0}
            className={`text-xs font-bold px-4 py-2 rounded-xl flex items-center gap-2 transition shadow-lg ${
              selectedCount > 0
                ? 'bg-gradient-to-r from-teal-500 to-cyan-500 text-slate-950 hover:brightness-110 shadow-teal-500/25 border border-teal-300 cursor-pointer animate-pulse'
                : 'bg-slate-900 text-slate-600 border border-slate-800 cursor-not-allowed'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Approve & Move to Vault ({selectedCount})</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 my-4 font-mono">
        <div className="flex items-center gap-1.5">
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilter(lvl)}
              className={`text-[11px] px-3 py-1 rounded-md font-semibold transition ${
                filter === lvl
                  ? 'bg-teal-500 text-slate-950 font-bold shadow-md shadow-teal-500/20'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search path, token, category..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-slate-950/80 border border-slate-800 text-slate-200 text-xs pl-8 pr-3 py-1.5 rounded-lg focus:outline-none focus:border-teal-500 w-64"
          />
        </div>
      </div>

      {/* Table Content with Framer Motion Layout Reordering */}
      <div className="overflow-x-auto rounded-xl border border-slate-800/80">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-bold uppercase text-[10px] tracking-wider">
            <tr>
              <th className="py-2.5 px-3 w-10">Select</th>
              <th className="py-2.5 px-3">Finding ID</th>
              <th className="py-2.5 px-3">Severity</th>
              <th className="py-2.5 px-3">Risk Score (R)</th>
              <th className="py-2.5 px-3">Category</th>
              <th className="py-2.5 px-3">Source Node</th>
              <th className="py-2.5 px-3">Masked Evidence</th>
              <th className="py-2.5 px-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-12 text-center text-slate-500 font-sans">
                  Zero findings matching active filters.
                </td>
              </tr>
            ) : (
              <AnimatePresence>
                {filtered.map((f) => {
                  const isCrit = f.severity === 'CRITICAL';
                  const isHigh = f.severity === 'HIGH';
                  const isExpanded = expandedId === f.id;

                  return (
                    <React.Fragment key={f.id}>
                      <motion.tr
                        layout
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95 }}
                        transition={{ duration: 0.25 }}
                        className={`cursor-pointer border-l-2 transition hover:bg-slate-900/70 ${
                          isCrit
                            ? 'border-l-rose-500/60'
                            : isHigh
                            ? 'border-l-amber-500/50'
                            : 'border-l-transparent'
                        } ${f.selected ? 'bg-teal-950/25' : ''}`}
                        onClick={() => onToggleSelect(f.id)}
                      >
                        <td className="py-2.5 px-3" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => onToggleSelect(f.id)}
                            className="text-slate-400 hover:text-teal-400 transition"
                          >
                            {f.selected ? (
                              <CheckSquare className="w-4 h-4 text-teal-400" />
                            ) : (
                              <Square className="w-4 h-4" />
                            )}
                          </button>
                        </td>

                        <td className="py-2.5 px-3 font-bold text-slate-200">
                          {f.id}
                        </td>

                        <td className="py-2.5 px-3">
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold tracking-wide uppercase ${
                              isCrit
                                ? 'bg-rose-950 border border-rose-600/70 text-rose-300'
                                : isHigh
                                ? 'bg-amber-950 border border-amber-600/70 text-amber-300'
                                : 'bg-teal-950 border border-teal-600/70 text-teal-300'
                            }`}
                          >
                            {isCrit && <ShieldAlert className="w-3 h-3 text-rose-400" />}
                            {isHigh && <AlertTriangle className="w-3 h-3 text-amber-400" />}
                            {!isCrit && !isHigh && <AlertCircle className="w-3 h-3 text-teal-400" />}
                            {f.severity}
                          </span>
                        </td>

                        <td className="py-2.5 px-3">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setExpandedId(isExpanded ? null : f.id);
                            }}
                            className="inline-flex items-center gap-1 font-black text-teal-300 hover:text-white transition group"
                            title="Click to view mathematical calculation"
                          >
                            <span>{f.score_r.toFixed(2)}</span>
                            <Calculator className="w-3 h-3 text-teal-500 group-hover:scale-110" />
                          </button>
                        </td>

                        <td className="py-2.5 px-3 font-sans font-medium text-slate-200">
                          {f.category}
                        </td>

                        <td
                          className="py-2.5 px-3 text-slate-400 text-[11px] max-w-xs truncate"
                          title={f.path}
                        >
                          {f.path.replace('/volume1/', '')}
                        </td>

                        <td className="py-2.5 px-3">
                          <ScrambleSecret text={f.masked_evidence} triggerKey={f.score_r} />
                        </td>

                        <td className="py-2.5 px-3 text-slate-400 text-[11px] font-sans">
                          {f.action}
                        </td>
                      </motion.tr>

                      {/* Expandable Math Calculation Drawer */}
                      {isExpanded && (
                        <tr className="bg-slate-900/80 border-b border-slate-800 text-[11px]">
                          <td colSpan={8} className="p-3">
                            <div className="bg-slate-950 border border-teal-500/30 rounded-xl p-3 flex flex-wrap items-center justify-between gap-4">
                              <div className="space-y-1">
                                <div className="font-bold text-teal-400 flex items-center gap-1.5">
                                  <Calculator className="w-3.5 h-3.5" />
                                  Mathematical Threat Score Formula: R = S × (1 + α_multi + β_public)
                                </div>
                                <div className="text-slate-300 text-[11px]">
                                  Base Severity (S) = <strong className="text-white">{isCrit ? '5.0' : isHigh ? '3.0' : '1.0'}</strong> ({f.severity})
                                  {' • '}
                                  Multi-User Factor (α) = <strong className="text-teal-400">{isShared ? '0.50' : '0.00'}</strong>
                                  {' • '}
                                  Public Guest Factor (β) = <strong className="text-amber-400">{isPublic ? '0.75' : '0.00'}</strong>
                                </div>
                              </div>
                              <div className="text-sm font-bold text-teal-300 font-mono">
                                Calculation: {isCrit ? '5.0' : isHigh ? '3.0' : '1.0'} × (1 + {isShared ? '0.50' : '0.00'} + {isPublic ? '0.75' : '0.00'}) = <span className="text-white bg-teal-950 px-2 py-0.5 rounded border border-teal-500">{f.score_r.toFixed(2)}</span>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </AnimatePresence>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
