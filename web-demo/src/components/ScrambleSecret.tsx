import React, { useState, useEffect } from 'react';
import { Lock } from 'lucide-react';

interface Props {
  text: string;
  triggerKey?: string | number;
}

const GLYPHS = '01#$!%&?*X_~<>[]';

export const ScrambleSecret: React.FC<Props> = ({ text, triggerKey }) => {
  const [displayText, setDisplayText] = useState(text);
  const [isLocked, setIsLocked] = useState(false);

  useEffect(() => {
    setIsLocked(false);
    let iteration = 0;
    const maxIterations = 8;
    const interval = setInterval(() => {
      iteration++;
      if (iteration >= maxIterations) {
        clearInterval(interval);
        setDisplayText(text);
        setIsLocked(true);
      } else {
        const scrambled = text
          .split('')
          .map((ch) => {
            if (ch === ' ' || ch === '-' || ch === '*' || ch === '[' || ch === ']') return ch;
            return GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
          })
          .join('');
        setDisplayText(scrambled);
      }
    }, 35);

    return () => clearInterval(interval);
  }, [text, triggerKey]);

  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[11px] bg-slate-950/80 px-2 py-0.5 rounded border border-teal-500/30 text-teal-300">
      <Lock className={`w-3 h-3 transition-transform ${isLocked ? 'text-teal-400 scale-100' : 'text-amber-400 scale-110 animate-spin'}`} />
      <span className="tracking-tight">{displayText}</span>
    </span>
  );
};
