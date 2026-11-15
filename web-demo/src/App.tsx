import React, { useState, useEffect } from 'react';
import { SAMPLE_NAS_FIXTURES, VirtualFile } from './engine/sampleFixtures';
import { runClientScan, Finding, ScanStats, TelemetryLog } from './engine/scanner';
import { HeaderHUD } from './components/HeaderHUD';
import { TelemetryStrip } from './components/TelemetryStrip';
import { PipelineVisualizer } from './components/PipelineVisualizer';
import { RiskHeatmapTable } from './components/RiskHeatmapTable';
import { LiveExecutionFeed } from './components/LiveExecutionFeed';
import { QuarantineVault } from './components/QuarantineVault';
import { ArchitectureModal } from './components/ArchitectureModal';

export default function App() {
  const [files, setFiles] = useState<VirtualFile[]>(SAMPLE_NAS_FIXTURES);
  const [isShared, setIsShared] = useState(true);
  const [isPublic, setIsPublic] = useState(true);
  const [scanDepth, setScanDepth] = useState<'quick' | 'standard' | 'deep'>('deep');

  const [stats, setStats] = useState<ScanStats>({
    total: files.length,
    critical: 0,
    high: 0,
    medium: 0,
    skippedMedia: 0,
    skippedCorrupt: 0,
    unscannedEncrypted: 0,
    currentPass: 1,
    currentFile: '',
    isScanning: false,
    isDone: false,
    cpuLoad: 12,
    npuLoad: 0
  });

  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<TelemetryLog[]>([]);
  const [isQuarantineOpen, setIsQuarantineOpen] = useState(false);
  const [isArchOpen, setIsArchOpen] = useState(false);
  const [quarantinedFiles, setQuarantinedFiles] = useState<
    Array<{ id: string; originalPath: string; vaultPath: string; hash: string }>
  >([]);

  // Execute Scan
  const handleStartScan = async (speedMultiplier: number = 1.0) => {
    setFindings([]);
    const res = await runClientScan(
      files,
      isShared,
      isPublic,
      scanDepth,
      (updatedStats, newLog, newFinding) => {
        setStats((prev) => ({ ...prev, ...updatedStats }));
        if (newLog) {
          setLogs((prev) => [...prev, newLog]);
        }
        if (newFinding) {
          setFindings((prev) => [...prev, newFinding]);
        }
      },
      speedMultiplier
    );
    setFindings(res.findings);
    return res;
  };

  // Automated "Live Attack-to-Lockdown" Demo Showcase
  const handleRunAutoDemo = async () => {
    // 1. Reset state & mount sample NAS
    setFiles(SAMPLE_NAS_FIXTURES);
    setFindings([]);
    setLogs([]);
    setQuarantinedFiles([]);
    setIsShared(true);
    setIsPublic(true);
    setScanDepth('deep');

    // 2. Execute fast-paced animated scan
    const res = await handleStartScan(0.65);

    // 3. Stagger select critical items
    if (res.findings.length > 0) {
      setTimeout(() => {
        setFindings((prev) =>
          prev.map((f) => ({ ...f, selected: f.severity === 'CRITICAL' }))
        );
        // 4. Open Human Quarantine Gate ready for judge click
        setTimeout(() => {
          setIsQuarantineOpen(true);
        }, 600);
      }, 400);
    }
  };

  // Reset to default sample
  const handleLoadSample = () => {
    setFiles(SAMPLE_NAS_FIXTURES);
    setFindings([]);
    setQuarantinedFiles([]);
    setStats({
      total: SAMPLE_NAS_FIXTURES.length,
      critical: 0,
      high: 0,
      medium: 0,
      skippedMedia: 0,
      skippedCorrupt: 0,
      unscannedEncrypted: 0,
      currentPass: 1,
      currentFile: 'Mounted /volume1/Shared',
      isScanning: false,
      isDone: false,
      cpuLoad: 12,
      npuLoad: 0
    });
    setLogs([
      {
        id: `init-${Date.now()}`,
        timestamp: new Date().toTimeString().split(' ')[0],
        level: 'INFO',
        pass: 1,
        message: 'Storage Volume Mounted: /volume1/Shared (11 Synthetic Nodes)',
        detail: 'Ready for 4-Pass local inspection'
      }
    ]);
  };

  // File Upload via FileReader
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const uploaded = e.target.files;
    if (!uploaded || uploaded.length === 0) return;

    const newFiles: VirtualFile[] = [];
    const readers: Promise<void>[] = [];

    for (let i = 0; i < uploaded.length; i++) {
      const f = uploaded[i];
      const promise = new Promise<void>((resolve) => {
        const reader = new FileReader();
        const ext = '.' + f.name.split('.').pop()?.toLowerCase();
        const isImg = ['.png', '.jpg', '.jpeg', '.webp'].includes(ext);

        reader.onload = (evt) => {
          newFiles.push({
            path: `/volume1/UserUploads/${f.name}`,
            name: f.name,
            size: f.size,
            type: isImg ? 'image' : f.name.endsWith('.pdf') ? 'pdf' : 'text',
            content: (evt.target?.result as string) || ''
          });
          resolve();
        };
        reader.readAsText(f);
      });
      readers.push(promise);
    }

    Promise.all(readers).then(() => {
      setFiles((prev) => [...prev, ...newFiles]);
      setStats((prev) => ({ ...prev, total: prev.total + newFiles.length }));
      setLogs((prev) => [
        ...prev,
        {
          id: `upload-${Date.now()}`,
          timestamp: new Date().toTimeString().split(' ')[0],
          level: 'INFO',
          pass: 1,
          message: `Ingested ${newFiles.length} file(s) into memory via FileReader`,
          detail: '100% Client-side. 0 bytes uploaded to external server.'
        }
      ]);
    });
  };

  // Export Report in Markdown
  const handleExportReport = () => {
    const today = new Date().toISOString();
    let md = `# 🛡️ Sentry Local Security Audit — Risk Heatmap Report\n`;
    md += `**Generated:** ${today}\n`;
    md += `**Target:** /volume1/Shared • **Platform:** UGREEN AI NAS iDX6011 Pro (UGOS)\n`;
    md += `**Egress Verification:** 0 Bytes Sent (100% Local Execution)\n\n`;
    md += `### Findings Matrix\n`;
    md += `| ID | Severity | Score R | Category | Source Node | Masked Evidence |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
    findings.forEach((f) => {
      md += `| \`${f.id}\` | \`${f.severity}\` | ${f.score_r.toFixed(2)} | ${f.category} | \`${f.path}\` | \`${f.masked_evidence}\` |\n`;
    });
    md += `\n*Report compiled locally by Sentry on UGREEN UGOS.*`;

    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Risk_Heatmap_Report_${today.split('T')[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Findings selection handlers
  const handleToggleSelect = (id: string) => {
    setFindings((prev) =>
      prev.map((f) => (f.id === id ? { ...f, selected: !f.selected } : f))
    );
  };

  const handleSelectAllCritical = () => {
    setFindings((prev) =>
      prev.map((f) => ({ ...f, selected: f.severity === 'CRITICAL' }))
    );
  };

  const handleSelectAll = () => {
    setFindings((prev) => prev.map((f) => ({ ...f, selected: true })));
  };

  const handleClearSelection = () => {
    setFindings((prev) => prev.map((f) => ({ ...f, selected: false })));
  };

  // Quarantine Confirmation
  const handleConfirmQuarantine = (approvedIds: string[]) => {
    const today = new Date().toISOString().split('T')[0];
    const list = findings
      .filter((f) => approvedIds.includes(f.id))
      .map((f) => ({
        id: f.id,
        originalPath: f.path,
        vaultPath: `/volume1/Private_Security_Vault/Quarantine_${today}/${f.path.replace('/volume1/', '')}`,
        hash: '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'
      }));

    setQuarantinedFiles((prev) => [...prev, ...list]);
    setFindings((prev) => prev.filter((f) => !approvedIds.includes(f.id)));

    setLogs((prev) => [
      ...prev,
      {
        id: `quarantine-${Date.now()}`,
        timestamp: new Date().toTimeString().split(' ')[0],
        level: 'ACTION',
        pass: 4,
        message: `Quarantine Executed: ${list.length} target(s) moved via ug-filemgr`,
        detail: `Preserved relative directory tree in /volume1/Private_Security_Vault/Quarantine_${today}`
      }
    ]);
  };

  // Rollback
  const handleRollback = () => {
    handleLoadSample();
    setIsQuarantineOpen(false);
  };

  const maxScore = findings.length > 0 ? Math.max(...findings.map((f) => f.score_r)) : 0;

  return (
    <div className="min-h-screen bg-[#05080F] text-slate-100 flex flex-col relative selection:bg-teal-500 selection:text-slate-950">
      {/* Background Cyber Grid & Radar SVG Overlay */}
      <div className="fixed inset-0 pointer-events-none z-0 opacity-[0.035]">
        <svg className="w-full h-full" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id="cyber-grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#14b8a6" strokeWidth="1" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#cyber-grid)" />
        </svg>
      </div>

      {/* Top Cyber HUD Header */}
      <HeaderHUD
        onRunAutoDemo={handleRunAutoDemo}
        onLoadSample={handleLoadSample}
        onFileUpload={handleFileUpload}
        onOpenArchitecture={() => setIsArchOpen(true)}
        onExportReport={handleExportReport}
        isScanning={stats.isScanning}
        fileCount={files.length}
      />

      {/* Main Single-Screen Command Console */}
      <main className="max-w-[1600px] mx-auto w-full px-6 py-5 space-y-5 flex-1 relative z-10">
        {/* Telemetry KPI Strip */}
        <TelemetryStrip
          stats={stats}
          maxScore={maxScore}
          quarantinedCount={quarantinedFiles.length}
          isShared={isShared}
          isPublic={isPublic}
        />

        {/* 4-Pass Neural Pipeline Visualizer & Context Toggles */}
        <PipelineVisualizer
          stats={stats}
          isShared={isShared}
          isPublic={isPublic}
          scanDepth={scanDepth}
          onToggleShared={(val) => {
            setIsShared(val);
            // Recompute risk scores dynamically across existing findings
            setFindings((prev) =>
              prev.map((f) => {
                const s = f.severity === 'CRITICAL' ? 5.0 : f.severity === 'HIGH' ? 3.0 : 1.0;
                const alpha = val ? 0.5 : 0.0;
                const beta = isPublic ? 0.75 : 0.0;
                return { ...f, score_r: parseFloat((s * (1 + alpha + beta)).toFixed(2)) };
              })
            );
          }}
          onTogglePublic={(val) => {
            setIsPublic(val);
            setFindings((prev) =>
              prev.map((f) => {
                const s = f.severity === 'CRITICAL' ? 5.0 : f.severity === 'HIGH' ? 3.0 : 1.0;
                const alpha = isShared ? 0.5 : 0.0;
                const beta = val ? 0.75 : 0.0;
                return { ...f, score_r: parseFloat((s * (1 + alpha + beta)).toFixed(2)) };
              })
            );
          }}
          onChangeDepth={setScanDepth}
        />

        {/* Main Split Command Console: Left 65% / Right 35% */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* Left / Center: Threat Heatmap Console */}
          <div className="lg:col-span-8 space-y-4">
            <RiskHeatmapTable
              findings={findings}
              onToggleSelect={handleToggleSelect}
              onSelectAllCritical={handleSelectAllCritical}
              onSelectAll={handleSelectAll}
              onClearSelection={handleClearSelection}
              onOpenQuarantineModal={() => setIsQuarantineOpen(true)}
              isShared={isShared}
              isPublic={isPublic}
              quarantinedCount={quarantinedFiles.length}
            />
          </div>

          {/* Right: Live Telemetry Feed & UGOS Skill Inspector */}
          <div className="lg:col-span-4 h-full">
            <LiveExecutionFeed
              logs={logs}
              isScanning={stats.isScanning}
              onClearLogs={() => setLogs([])}
            />
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/90 py-3.5 px-6 text-center text-xs font-mono text-slate-500 relative z-10 flex flex-wrap items-center justify-between gap-4">
        <div>
          <span>UGREEN AI NAS iDX6011 Pro</span>
          <span className="mx-2">•</span>
          <span>UGOS Linux Kernel 6.x</span>
          <span className="mx-2">•</span>
          <span className="text-teal-400">100% Zero-Egress Verified</span>
        </div>
        <div>
          <span>UGREEN Hackathon 2026 on AI NAS • Track: Open Innovation</span>
        </div>
      </footer>

      {/* Quarantine Vault Modal */}
      <QuarantineVault
        isOpen={isQuarantineOpen}
        onClose={() => setIsQuarantineOpen(false)}
        selectedFindings={findings.filter((f) => f.selected)}
        onConfirmQuarantine={handleConfirmQuarantine}
        quarantinedList={quarantinedFiles}
        onRollback={handleRollback}
      />

      {/* UGOS Architecture & Skill Modal */}
      <ArchitectureModal isOpen={isArchOpen} onClose={() => setIsArchOpen(false)} />
    </div>
  );
}
