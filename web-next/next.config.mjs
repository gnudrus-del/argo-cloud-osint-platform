/** @type {import('next').NextConfig} */

// Il backend Python (osint_bot.web) espone /api/*. In dev proxiamo le chiamate
// così il frontend gira su :3000 e parla col backend su :8765 senza CORS.
const API_BASE = process.env.ARGO_API_BASE || "http://127.0.0.1:8765";

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${API_BASE}/api/:path*` },
    ];
  },
};

export default nextConfig;
