/** @type {import('next').NextConfig} */
const basePath = process.env.NEXT_PUBLIC_BASE_PATH || '';

module.exports = {
  reactStrictMode: true,
  basePath: basePath || undefined,
  experimental: { typedRoutes: false }
};
