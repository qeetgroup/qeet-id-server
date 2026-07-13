import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  transpilePackages: ["@qeetrix/ui"],
  allowedDevOrigins: ["id.qeet.localhost"],
};

export default nextConfig;
