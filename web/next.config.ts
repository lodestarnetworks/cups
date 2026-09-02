import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Produce a self-contained Node.js runtime for private bare-metal/VPS
  // deployments. The Cloudflare/Sites build remains driven by vite.config.ts.
  output: 'standalone',
};

export default nextConfig;
