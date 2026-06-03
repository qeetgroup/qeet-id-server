import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

// The session and PKCE cookies are encrypted (AES-256-GCM) and authenticated, so
// the tokens they carry are opaque and tamper-evident. Runs in the Node runtime
// (route handlers + Server Components) — not in edge middleware, which only
// checks cookie presence.

function keyFromSecret(secret: string): Buffer {
  return createHash("sha256").update(secret).digest(); // 32 bytes for AES-256
}

/** seal encrypts a JSON value into `iv.tag.ciphertext` (all base64url). */
export function seal(data: unknown, secret: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", keyFromSecret(secret), iv);
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, ciphertext].map((b) => b.toString("base64url")).join(".");
}

/** open decrypts and parses a sealed value, or returns null if invalid/tampered. */
export function open<T>(token: string, secret: string): T | null {
  try {
    const [ivB, tagB, ctB] = token.split(".");
    if (!ivB || !tagB || !ctB) return null;
    const decipher = createDecipheriv("aes-256-gcm", keyFromSecret(secret), Buffer.from(ivB, "base64url"));
    decipher.setAuthTag(Buffer.from(tagB, "base64url"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(ctB, "base64url")), decipher.final()]);
    return JSON.parse(plaintext.toString("utf8")) as T;
  } catch {
    return null;
  }
}
