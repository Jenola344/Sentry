import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * `PREVIEW_ALLOWED_HOSTS` lets a hosted preview (or any tunnelled hostname) reach
 * the dev server without committing a machine-specific hostname into the repo.
 * Vite only accepts the exact hosts listed, never a wildcard.
 */
export default defineConfig(() => {
  const allowedHosts = (process.env.PREVIEW_ALLOWED_HOSTS ?? '')
    .split(',')
    .map((host) => host.trim())
    .filter(Boolean);

  return {
    plugins: [react()],
    base: './',
    server: {
      port: 3000,
      host: true,
      ...(allowedHosts.length > 0 ? { allowedHosts } : {})
    }
  };
});
