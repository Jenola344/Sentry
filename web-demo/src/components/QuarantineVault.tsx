import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Finding } from '../engine/scanner';
import {
  ShieldCheck,
  Undo2,
  Lock,
  CheckCircle2,
  X,
  FileCheck2,
  FolderTree,
  AlertOctagon
} from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  selectedFindings: Finding[];
  onConfirmQuarantine: (findingIds: string[]) => void;
  quarantinedList: Array<{ id: string; originalPath: string; vaultPath: string; hash: string }>;
  onRollback: () => void;
}

export const QuarantineVault: React.FC<Props> = ({
  isOpen,
  onClose,
  selectedFindings,
  onConfirmQuarantine,
  quarantinedList,
  onRollback
}) => {
  const [confirmed, setConfirmed] = useState(false);
  const [activeTab, setActiveTab] = useState<'GATE' | 'VAULT_TREE' | 'MANIFEST'>('GATE');

  if (!isOpen) return null;

  const today = new Date().toISOString().split('T')[0];
  const vaultRoot = `/volume1/Private_Security_Vault/Quarantine_${today}`;

  const handleApprove = () => {
    onConfirmQuarantine(selectedFindings.map((f) => f.id));
    setConfirmed(true);
    setActiveTab('VAULT_TREE');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        className="glass-panel border-teal-500/40 rounded-2xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh] font-mono"
      >
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-teal-950/90 border border-teal-500/50 flex items-center justify-center text-teal-400">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                HUMAN-IN-THE-LOOP QUARANTINE GATE
                <span className="text-[10px] bg-teal-950 text-teal-300 px-2 py-0.5 rounded border border-teal-500/30">
                  ug-filemgr
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5 font-sans">
                Non-destructive atomic isolation preserving relative hierarchy to eliminate filename collisions.
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition p-1">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 bg-slate-950/40 px-5 gap-4 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('GATE')}
            className={`py-3 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'GATE'
                ? 'border-teal-400 text-teal-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <AlertOctagon className="w-3.5 h-3.5" />
            1. Authorize Gate
          </button>
          <button
            onClick={() => setActiveTab('VAULT_TREE')}
            className={`py-3 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'VAULT_TREE'
                ? 'border-teal-400 text-teal-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FolderTree className="w-3.5 h-3.5" />
            2. Vault Hierarchy Tree
          </button>
          <button
            onClick={() => setActiveTab('MANIFEST')}
            className={`py-3 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'MANIFEST'
                ? 'border-teal-400 text-teal-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCheck2 className="w-3.5 h-3.5" />
            3. Reversible Manifest
          </button>
        </div>

        {/* Body Content */}
        <div className="p-6 overflow-y-auto space-y-4 text-xs">
          {activeTab === 'GATE' && (
            <div className="space-y-4">
              <div className="bg-amber-950/30 border border-amber-600/40 rounded-xl p-4 text-amber-200/90 leading-relaxed font-sans">
                <strong className="text-amber-100 block mb-1 font-semibold flex items-center gap-1.5">
                  <AlertOctagon className="w-4 h-4 text-amber-400" />
                  Zero-Accident Autonomous Safety Invariant:
                </strong>
                Sentry will never move, rename, or delete files automatically. You must review the flagged targets and explicitly approve the isolation move.
              </div>

              <div>
                <h4 className="font-bold text-slate-200 mb-2">
                  Target Files for Lockdown ({selectedFindings.length}):
                </h4>
                <div className="bg-slate-950 border border-slate-800 rounded-xl max-h-48 overflow-y-auto divide-y divide-slate-800">
                  {selectedFindings.map((f) => (
                    <div key={f.id} className="p-2.5 flex items-center justify-between hover:bg-slate-900/50">
                      <div>
                        <span className="text-teal-400 font-bold mr-2">{f.id}</span>
                        <span className="text-slate-300">{f.path}</span>
                      </div>
                      <span className="text-[10px] bg-rose-950 text-rose-300 px-2 py-0.5 rounded border border-rose-800">
                        {f.severity} (R={f.score_r.toFixed(2)})
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-slate-300">
                <span className="text-slate-400 block mb-1 font-semibold">Isolation Destination:</span>
                <code className="text-teal-400 font-bold">{vaultRoot}/</code>
              </div>
            </div>
          )}

          {activeTab === 'VAULT_TREE' && (
            <div className="space-y-3 font-mono">
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-slate-300 leading-relaxed">
                <div className="text-teal-400 font-bold mb-2">
                  📁 {vaultRoot}/
                </div>
                <div className="pl-4 space-y-1 text-slate-400">
                  <div>└── 📁 Shared/</div>
                  <div className="pl-4">├── 📁 Projects/</div>
                  <div className="pl-8 text-teal-300">├── 📁 app1/ &rarr; 📄 .env <span className="text-slate-500">(OpenAI Key)</span></div>
                  <div className="pl-8 text-teal-300">└── 📁 app2/ &rarr; 📄 .env <span className="text-slate-500">(AWS Key - Collision-Safe)</span></div>
                  <div className="pl-4 text-teal-300">├── 📁 Backups/ &rarr; 📄 crypto_wallet_recovery.txt</div>
                  <div className="pl-4 text-slate-300">└── 📄 quarantine-manifest.md <span className="text-amber-400">(SHA-256 Ledger)</span></div>
                </div>
              </div>
              <p className="text-slate-400 text-xs font-sans">
                Notice how duplicate filenames (<code className="text-teal-400">app1/.env</code> vs <code className="text-teal-400">app2/.env</code>) safely coexist in separate mirrored directories without overwriting each other.
              </p>
            </div>
          )}

          {activeTab === 'MANIFEST' && (
            <div className="space-y-3 font-mono">
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-[11px] leading-relaxed text-slate-300 overflow-x-auto">
                <div className="text-teal-400 font-bold mb-1"># Sentry Quarantine Manifest</div>
                <div className="text-slate-500 mb-3">Timestamp: {new Date().toISOString()} | Target: {vaultRoot}</div>
                <table className="w-full text-left">
                  <thead className="border-b border-slate-800 text-slate-400">
                    <tr>
                      <th className="py-1">ID</th>
                      <th className="py-1">Original Path</th>
                      <th className="py-1">SHA-256 (Checksum)</th>
                      <th className="py-1">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {selectedFindings.map((f, i) => (
                      <tr key={f.id} className="text-slate-300">
                        <td className="py-1 text-teal-400 font-bold">{f.id}</td>
                        <td className="py-1 truncate max-w-xs">{f.path}</td>
                        <td className="py-1 text-slate-500 truncate max-w-xs">
                          {`4f53cda18c2baa0c0354bb5f9a3ecbe5...${i}`}
                        </td>
                        <td className="py-1 text-teal-400 font-bold">QUARANTINED</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* 1-Click Rollback Action */}
              <div className="pt-2 flex justify-end">
                <button
                  onClick={onRollback}
                  className="bg-amber-950/70 hover:bg-amber-900 border border-amber-600/50 text-amber-200 px-4 py-2 rounded-xl flex items-center gap-2 font-bold transition shadow-lg"
                >
                  <Undo2 className="w-4 h-4" />
                  Simulate 1-Click Rollback via ug-filemgr
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div className="text-xs text-slate-400">
            {confirmed ? (
              <span className="flex items-center gap-1.5 text-teal-400 font-bold">
                <CheckCircle2 className="w-4 h-4" />
                Files Successfully Isolated in Private Vault
              </span>
            ) : (
              <span>Ready for human authentication.</span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-xl border border-slate-700 text-slate-300 hover:bg-slate-800 transition text-xs font-medium"
            >
              {confirmed ? 'Close' : 'Cancel'}
            </button>
            {!confirmed && (
              <button
                onClick={handleApprove}
                disabled={selectedFindings.length === 0}
                className="bg-gradient-to-r from-teal-500 to-cyan-500 text-slate-950 hover:brightness-110 font-bold px-5 py-2 rounded-xl transition text-xs flex items-center gap-1.5 shadow-lg shadow-teal-500/25 border border-teal-300 cursor-pointer"
              >
                <ShieldCheck className="w-4 h-4" />
                Authorize & Move Files
              </button>
            )}
          </div>
        </div>
      </motion.div>
    </div>
  );
};
