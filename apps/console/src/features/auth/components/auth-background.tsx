import { lazy, Suspense, useEffect, useState } from "react";

// three/R3F is heavy + WebGL-only, so load the Beams canvas lazily, client-side only.
const Beams = lazy(() => import("./Beams"));

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
  );
}

/**
 * Animated light-beams background for the auth (sign-in / sign-up) screens.
 * Solid black renders on the server / pre-hydration; the WebGL canvas mounts
 * only after the client hydrates. Reduced-motion freezes the beams (speed 0).
 */
export function AuthBackground() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 z-0 bg-black">
      {mounted && (
        <Suspense fallback={null}>
          <Beams
            beamWidth={3}
            beamHeight={30}
            beamNumber={20}
            lightColor="#ffffff"
            speed={prefersReducedMotion() ? 0 : 2}
            noiseIntensity={1.75}
            scale={0.2}
            rotation={30}
          />
        </Suspense>
      )}
    </div>
  );
}
