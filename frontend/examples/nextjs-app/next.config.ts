import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The @qeetid/* packages are workspace dependencies shipped as ESM; let Next
  // transpile them so they work in both the Node and Edge (middleware) runtimes.
  transpilePackages: ["@qeetid/react", "@qeetid/nextjs", "@qeetid/sdk"],
};

export default nextConfig;
