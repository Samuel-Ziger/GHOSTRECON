/** @type {import('next').NextConfig} */
const basePath = process.env.NEXT_PUBLIC_BASE_PATH || '';

const nextConfig = {
  reactStrictMode: true,
  basePath: basePath || undefined,
  experimental: {
    typedRoutes: false
  }
};

export default nextConfig;
