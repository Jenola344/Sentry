import React, { useEffect, useRef } from 'react';

/**
 * Purely decorative background: drifting colour fields, a masked blueprint grid,
 * a cursor-tracked spotlight and a slow scanline. Fixed, non-interactive, and it
 * respects prefers-reduced-motion via CSS.
 */
export const AmbientBackdrop: React.FC = () => {
  const spotlightRef = useRef<HTMLDivElement>(null);
  const frameRef = useRef<number>(0);

  useEffect(() => {
    const handlePointerMove = (event: PointerEvent) => {
      if (frameRef.current) return;
      frameRef.current = window.requestAnimationFrame(() => {
        frameRef.current = 0;
        const node = spotlightRef.current;
        if (!node) return;
        node.style.setProperty('--mx', `${event.clientX}px`);
        node.style.setProperty('--my', `${event.clientY}px`);
      });
    };

    window.addEventListener('pointermove', handlePointerMove, { passive: true });
    return () => {
      window.removeEventListener('pointermove', handlePointerMove);
      if (frameRef.current) window.cancelAnimationFrame(frameRef.current);
    };
  }, []);

  return (
    <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden" aria-hidden="true">
      {/* Base wash */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(13,148,136,0.12),transparent_58%)]" />

      {/* Drifting colour fields */}
      <div className="aurora aurora-a -left-40 -top-52 h-[36rem] w-[36rem]" />
      <div className="aurora aurora-b -right-44 top-24 h-[32rem] w-[32rem]" />
      <div className="aurora aurora-c left-1/3 top-[65%] h-[30rem] w-[30rem]" />

      {/* Blueprint grid */}
      <div className="hud-grid absolute inset-0 opacity-[0.45]" />

      {/* Cursor glow */}
      <div ref={spotlightRef} className="spotlight absolute inset-0" />

      {/* Slow scanline sweep */}
      <div className="scanline-overlay absolute inset-0" />

      {/* Vignette keeps the edges calm */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,transparent_42%,rgba(2,6,12,0.8)_100%)]" />
    </div>
  );
};
