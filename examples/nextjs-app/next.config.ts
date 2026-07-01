import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The @qeet-id/* packages are workspace dependencies shipped as ESM; let Next
  // transpile them so they work in both the Node and Edge (middleware) runtimes.
  transpilePackages: ["@qeet-id/react", "@qeet-id/nextjs", "@qeet-id/sdk"],
};

export default nextConfig;
