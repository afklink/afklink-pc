/**
 * Checking a Tauri updater signature the way the app's updater will (its own code,
 * `updater/manifest.rs` → `minisign-verify`), so a release
 * signed with a key the app does not trust is caught before it is published, not by every installed
 * copy refusing it. As in the app, only a prehashed (`ED`) signature is accepted — what the Tauri
 * CLI writes; a legacy (`Ed`) one is refused ([`assertPrehashed`]).
 *
 * Formats (minisign, as `cargo tauri signer` writes them, each file base64 of the minisign text):
 *
 * - public key: `untrusted comment: …\n` + base64(`Ed` ‖ key id (8) ‖ Ed25519 key (32));
 * - signature: `untrusted comment: …\n` + base64(algorithm (2) ‖ key id (8) ‖ signature (64)) +
 *   `\ntrusted comment: …\n` + base64(global signature (64)).
 *
 * Algorithm `ED` signs the BLAKE2b-512 of the file (what the Tauri CLI produces), `Ed` the file
 * itself. The global signature covers the signature and the trusted comment, so the comment's
 * `file:` and `version:` fields can be believed once it verifies.
 */
import { createHash, createPublicKey, verify } from "node:crypto";

export interface PublicKey {
  keyId: Buffer;
  key: Buffer;
}

export interface Signature {
  algorithm: "Ed" | "ED";
  keyId: Buffer;
  signature: Buffer;
  trustedComment: string;
  globalSignature: Buffer;
}

const UNTRUSTED = "untrusted comment: ";
const TRUSTED = "trusted comment: ";

/** The minisign text inside a Tauri key or signature file (base64 of it). */
function decodeOuter(base64Text: string, what: string): string[] {
  const compact = base64Text.trim();
  if (!/^[A-Za-z0-9+/]+=*$/.test(compact)) throw new Error(`${what}: не base64`);
  return Buffer.from(compact, "base64").toString("utf8").replace(/\r\n/g, "\n").split("\n");
}

function decodeInner(line: string | undefined, bytes: number, what: string): Buffer {
  const raw = Buffer.from((line ?? "").trim(), "base64");
  if (raw.length !== bytes) throw new Error(`${what}: ${raw.length} байт вместо ${bytes}`);
  return raw;
}

/** The key id as minisign prints it («minisign public key: 3A1B…»): little-endian, upper hex. */
export function keyIdHex(keyId: Buffer): string {
  return Buffer.from(keyId).reverse().toString("hex").toUpperCase();
}

/** A public key as `cargo tauri signer generate` writes `<key>.pub`. */
export function decodePublicKey(base64Text: string): PublicKey {
  const [comment, body] = decodeOuter(base64Text, "открытый ключ");
  if (!comment?.startsWith(UNTRUSTED)) throw new Error("открытый ключ: нет строки комментария");
  const raw = decodeInner(body, 42, "открытый ключ");
  if (raw.subarray(0, 2).toString("latin1") !== "Ed") {
    throw new Error("открытый ключ: не Ed25519-ключ minisign");
  }
  return { keyId: raw.subarray(2, 10), key: raw.subarray(10, 42) };
}

/** A signature as `cargo tauri signer sign` writes `<file>.sig`. */
export function decodeSignature(base64Text: string): Signature {
  const [untrusted, body, trusted, global] = decodeOuter(base64Text, "подпись");
  if (!untrusted?.startsWith(UNTRUSTED)) throw new Error("подпись: нет строки комментария");
  if (!trusted?.startsWith(TRUSTED)) throw new Error("подпись: нет строки trusted comment");
  const raw = decodeInner(body, 74, "подпись");
  const algorithm = raw.subarray(0, 2).toString("latin1");
  if (algorithm !== "Ed" && algorithm !== "ED") {
    throw new Error(`подпись: неизвестный алгоритм «${algorithm}»`);
  }
  return {
    algorithm,
    keyId: raw.subarray(2, 10),
    signature: raw.subarray(10, 74),
    trustedComment: trusted.slice(TRUSTED.length),
    globalSignature: decodeInner(global, 64, "подпись (global)"),
  };
}

/** A `key:value` field of the trusted comment (tab-separated: `timestamp:…\tfile:…`). */
export function trustedField(sig: Signature, name: string): string | undefined {
  for (const field of sig.trustedComment.split("\t")) {
    if (field.startsWith(`${name}:`)) return field.slice(name.length + 1);
  }
  return undefined;
}

function ed25519Verify(message: Uint8Array, key: Buffer, signature: Buffer): boolean {
  const publicKey = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: key.toString("base64url") },
    format: "jwk",
  });
  return verify(null, message, publicKey, signature);
}

/**
 * Throws unless `sig` is prehashed (`ED`), as the app requires (`updater/manifest.rs`,
 * `verify_signature`): a legacy `Ed` signature is refused there, since the algorithm bytes are not
 * signed and a flip from `ED` would pass the exe's digest off as the exe.
 */
export function assertPrehashed(sig: Signature): void {
  if (sig.algorithm !== "ED") {
    throw new Error(
      `подпись устаревшего вида («${sig.algorithm}», без предварительного хеша): приложение ` +
        "принимает только «ED», какую пишет `cargo tauri signer sign`",
    );
  }
}

/**
 * Throws with the reason unless `sig` is a valid prehashed signature of `data` by `pk` — the
 * checks the app makes, legacy `Ed` refused ([`assertPrehashed`]).
 */
export function verifySignature(data: Uint8Array, sig: Signature, pk: PublicKey): void {
  assertPrehashed(sig);
  if (!sig.keyId.equals(pk.keyId)) {
    throw new Error(
      `подписано ключом ${keyIdHex(sig.keyId)}, а открытый ключ — ${keyIdHex(pk.keyId)}`,
    );
  }
  const message = createHash("blake2b512").update(data).digest();
  if (!ed25519Verify(message, pk.key, sig.signature)) {
    throw new Error("подпись не сходится с файлом");
  }
  const covered = Buffer.concat([sig.signature, Buffer.from(sig.trustedComment, "utf8")]);
  if (!ed25519Verify(covered, pk.key, sig.globalSignature)) {
    throw new Error("подпись trusted comment не сходится");
  }
}
