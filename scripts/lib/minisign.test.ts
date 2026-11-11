/**
 * The checker against signatures made here in the minisign format. Compatibility with what
 * `cargo tauri signer` really writes is checked by `release-build.ts` itself on every release (and was
 * with a throwaway key when this was written); these pin the checker's own logic.
 */
import { describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  assertPrehashed,
  decodePublicKey,
  decodeSignature,
  keyIdHex,
  trustedField,
  verifySignature,
} from "./minisign";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const RAW_KEY = Buffer.from(publicKey.export({ format: "jwk" }).x ?? "", "base64url");
const KEY_ID = Buffer.from("0102030405060708", "hex");
const b64 = (text: string) => Buffer.from(text, "utf8").toString("base64");

const PUB = b64(
  `untrusted comment: minisign public key: ${keyIdHex(KEY_ID)}\n` +
    `${Buffer.concat([Buffer.from("Ed"), KEY_ID, RAW_KEY]).toString("base64")}\n`,
);

function signed(
  data: Buffer,
  {
    algorithm = "ED",
    trusted = "timestamp:1700000000\tfile:AFKLink-0.1.0.exe",
    keyId = KEY_ID,
  } = {},
): string {
  const message = algorithm === "ED" ? createHash("blake2b512").update(data).digest() : data;
  const sig = sign(null, message, privateKey);
  const global = sign(null, Buffer.concat([sig, Buffer.from(trusted, "utf8")]), privateKey);
  return b64(
    "untrusted comment: signature from tauri secret key\n" +
      `${Buffer.concat([Buffer.from(algorithm), keyId, sig]).toString("base64")}\n` +
      `trusted comment: ${trusted}\n${global.toString("base64")}\n`,
  );
}

const DATA = Buffer.from("MZ… the exe");

describe("verifySignature", () => {
  test("a prehashed signature (what the Tauri CLI writes) verifies", () => {
    const sig = decodeSignature(signed(DATA));
    expect(sig.algorithm).toBe("ED");
    expect(trustedField(sig, "file")).toBe("AFKLink-0.1.0.exe");
    expect(trustedField(sig, "version")).toBeUndefined();
    expect(() => verifySignature(DATA, sig, decodePublicKey(PUB))).not.toThrow();
  });

  test("a legacy (Ed) signature is refused, valid as it is, as the app refuses it", () => {
    const sig = decodeSignature(signed(DATA, { algorithm: "Ed" }));
    expect(sig.algorithm).toBe("Ed");
    expect(() => verifySignature(DATA, sig, decodePublicKey(PUB))).toThrow(/устаревшего вида/);
    expect(() => assertPrehashed(sig)).toThrow(/только «ED»/);
  });

  test("assertPrehashed takes ED and refuses Ed", () => {
    expect(() => assertPrehashed(decodeSignature(signed(DATA)))).not.toThrow();
    expect(() => assertPrehashed(decodeSignature(signed(DATA, { algorithm: "Ed" })))).toThrow(
      /«Ed», без предварительного хеша/,
    );
  });

  test("another file does not", () => {
    const sig = decodeSignature(signed(DATA));
    expect(() => verifySignature(Buffer.from("MZ… another"), sig, decodePublicKey(PUB))).toThrow(
      /не сходится с файлом/,
    );
  });

  test("an edited trusted comment does not", () => {
    const good = Buffer.from(signed(DATA), "base64").toString("utf8");
    const forged = b64(good.replace("file:AFKLink-0.1.0.exe", "file:AFKLink-9.9.9.exe"));
    const sig = decodeSignature(forged);
    expect(() => verifySignature(DATA, sig, decodePublicKey(PUB))).toThrow(/trusted comment/);
  });

  test("another key does not, and says which", () => {
    const sig = decodeSignature(signed(DATA, { keyId: Buffer.from("1111111111111111", "hex") }));
    expect(() => verifySignature(DATA, sig, decodePublicKey(PUB))).toThrow(/1111111111111111/);
  });
});

describe("decoding", () => {
  test("the key id reads as minisign prints it", () => {
    expect(keyIdHex(KEY_ID)).toBe("0807060504030201");
    expect(decodePublicKey(PUB).keyId.equals(KEY_ID)).toBe(true);
  });

  test("garbage is refused with a reason", () => {
    expect(() => decodePublicKey("not base64!")).toThrow(/base64/);
    expect(() => decodePublicKey(b64("untrusted comment: x\nAAAA\n"))).toThrow(/байт/);
    expect(() => decodeSignature(PUB)).toThrow();
  });

  test("fields of the trusted comment", () => {
    const sig = decodeSignature(
      signed(DATA, { trusted: "timestamp:1\tfile:a.exe\tversion:0.1.0" }),
    );
    expect(trustedField(sig, "version")).toBe("0.1.0");
    expect(trustedField(sig, "timestamp")).toBe("1");
    expect(trustedField(sig, "missing")).toBeUndefined();
  });
});
