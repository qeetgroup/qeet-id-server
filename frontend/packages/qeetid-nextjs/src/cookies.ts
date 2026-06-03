// The session and PKCE cookies are encrypted (AES-256-GCM) and authenticated.
// Implemented with Web Crypto (globalThis.crypto.subtle) so the same code runs
// in both the Node runtime (route handlers, Server Components) and the Edge
// runtime (middleware, which refreshes the session). seal/open are async.

async function importKey(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** seal encrypts a JSON value into `iv.ciphertext` (base64url; GCM tag embedded). */
export async function seal(data: unknown, secret: string): Promise<string> {
  const key = await importKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  return `${b64url(iv)}.${b64url(ciphertext)}`;
}

/** open decrypts and parses a sealed value, or returns null if invalid/tampered. */
export async function open<T>(token: string, secret: string): Promise<T | null> {
  try {
    const [ivB, ctB] = token.split(".");
    if (!ivB || !ctB) return null;
    const key = await importKey(secret);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64url(ivB) },
      key,
      fromB64url(ctB),
    );
    return JSON.parse(new TextDecoder().decode(plaintext)) as T;
  } catch {
    return null;
  }
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s: string): ArrayBuffer {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
