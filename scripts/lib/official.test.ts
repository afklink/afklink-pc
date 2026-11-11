/**
 * The release rules against keys and signatures made here in the Tauri signer's format (base64 of
 * the minisign text, prehashed `ED`, trusted comment `timestamp:…\tfile:…\tversion:…`).
 */
import { describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { keyIdHex } from "./minisign";
import {
  assertEmbeddedKeys,
  assertKeyFiles,
  checkReleaseSignature,
  dryRunExeName,
  parseKeyLine,
  releaseAssets,
  releaseBody,
  releaseExeName,
  sha256Of,
  sha256Sums,
  tagVersion,
} from "./official";

const b64 = (text: string) => Buffer.from(text, "utf8").toString("base64");

function keypair(idHex: string): { line: string; keyId: Buffer; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x ?? "", "base64url");
  const keyId = Buffer.from(idHex, "hex");
  const line = b64(
    `untrusted comment: minisign public key: ${keyIdHex(keyId)}\n` +
      `${Buffer.concat([Buffer.from("Ed"), keyId, raw]).toString("base64")}\n`,
  );
  return { line, keyId, privateKey };
}

const PROD = keypair("0102030405060708");
const TEST = keypair("1112131415161718");
const prodKey = () => {
  const k = parseKeyLine(`# comment\n${PROD.line}\n`, "updater.pub");
  if (k === null) throw new Error("no key");
  return k;
};
const testKey = () => parseKeyLine(TEST.line, "updater-test.pub");

function signed(
  data: Buffer,
  trusted: string,
  { pair = PROD, algorithm = "ED" }: { pair?: typeof PROD; algorithm?: string } = {},
): string {
  const message = algorithm === "ED" ? createHash("blake2b512").update(data).digest() : data;
  const sig = sign(null, message, pair.privateKey);
  const global = sign(null, Buffer.concat([sig, Buffer.from(trusted, "utf8")]), pair.privateKey);
  return b64(
    "untrusted comment: signature from tauri secret key\n" +
      `${Buffer.concat([Buffer.from(algorithm), pair.keyId, sig]).toString("base64")}\n` +
      `trusted comment: ${trusted}\n${global.toString("base64")}\n`,
  );
}

const EXE = Buffer.from(`MZ... ${PROD.line} ... the app`);
const GOOD = "timestamp:1700000000\tfile:AFKLink-1.2.3.exe\tversion:1.2.3";

describe("names", () => {
  test("release tags are v and a plain version", () => {
    expect(tagVersion("v1.2.3")).toBe("1.2.3");
    expect(tagVersion("v0.10.0")).toBe("0.10.0");
    for (const bad of ["1.2.3", "v1.2", "v01.2.3", "v1.2.3-rc1", "v1.2.3\n", "refs/tags/v1.2.3"]) {
      expect(tagVersion(bad)).toBeNull();
    }
  });

  test("the release exe and a dry run's are told apart", () => {
    expect(releaseExeName("1.2.3")).toBe("AFKLink-1.2.3.exe");
    expect(dryRunExeName("1.2.3", "abcdef0", true)).toBe(
      "AFKLink-1.2.3-untagged-abcdef0-dirty.exe",
    );
    expect(releaseAssets("1.2.3")).toEqual([
      "AFKLink-1.2.3.exe",
      "AFKLink-1.2.3.exe.sig",
      "AFKLink-1.2.3.cdx.json",
      "THIRD-PARTY-NOTICES.txt",
      "SHA256SUMS",
    ]);
  });
});

describe("key files", () => {
  test("one key line among comments; none; more than one is refused", () => {
    expect(prodKey().line).toBe(PROD.line);
    expect(parseKeyLine("# nothing yet\n\n", "x")).toBeNull();
    expect(() => parseKeyLine(`${PROD.line}\n${TEST.line}\n`, "x")).toThrow(/2 key lines/);
    expect(() => parseKeyLine("not-a-key\n", "x")).toThrow(/not a minisign public key/);
  });

  test("a release needs the update key, and a test key that is another key", () => {
    expect(() => assertKeyFiles(null, testKey())).toThrow(/holds no key/);
    expect(() => assertKeyFiles(prodKey(), prodKey())).toThrow(/same key/);
    expect(assertKeyFiles(prodKey(), testKey()).join(" ")).toContain("never trusted");
    expect(assertKeyFiles(prodKey(), null).join(" ")).toContain("holds no key");
  });

  test("the exe carries the update key and not the test key", () => {
    expect(() => assertEmbeddedKeys(EXE, prodKey(), testKey())).not.toThrow();
    const both = Buffer.concat([EXE, Buffer.from(TEST.line)]);
    expect(() => assertEmbeddedKeys(both, prodKey(), testKey())).toThrow(/test key/);
    const testOnly = Buffer.from(`MZ ${TEST.line}`);
    expect(() => assertEmbeddedKeys(testOnly, prodKey(), testKey())).toThrow(/test key/);
    expect(() => assertEmbeddedKeys(Buffer.from("MZ"), prodKey(), null)).toThrow(/update key/);
  });
});

describe("the release signature, as the app checks it", () => {
  const key = prodKey().key;

  test("the signer's signature of the exe, its file and its version passes", () => {
    const r = checkReleaseSignature(EXE, signed(EXE, GOOD), key, "1.2.3");
    expect(r.keyId).toBe(keyIdHex(PROD.keyId));
    expect(r.trustedComment).toBe(GOOD);
    const v = "timestamp:1\tfile:AFKLink-1.2.3.exe\tversion:v1.2.3";
    expect(() => checkReleaseSignature(EXE, signed(EXE, v), key, "1.2.3")).not.toThrow();
  });

  test("another file name, another version or none is refused", () => {
    const cases: [string, RegExp][] = [
      ["timestamp:1\tfile:AFKLink-1.2.2.exe\tversion:1.2.3", /names the file/],
      ["timestamp:1\tfile:AFKLink-1.2.3-untagged-abcdef0.exe\tversion:1.2.3", /names the file/],
      ["timestamp:1\tfile:afklink-1.2.3.exe\tversion:1.2.3", /names the file/],
      ["timestamp:1\tfile:AFKLink-1.2.3.exe", /names the version/],
      ["timestamp:1\tfile:AFKLink-1.2.3.exe\tversion:1.2.4", /names the version/],
    ];
    for (const [trusted, why] of cases) {
      expect(() => checkReleaseSignature(EXE, signed(EXE, trusted), key, "1.2.3")).toThrow(why);
    }
  });

  test("other bytes, the test key, a legacy signature or an edited comment are refused", () => {
    expect(() =>
      checkReleaseSignature(Buffer.from("MZ other"), signed(EXE, GOOD), key, "1.2.3"),
    ).toThrow();
    expect(() =>
      checkReleaseSignature(EXE, signed(EXE, GOOD, { pair: TEST }), key, "1.2.3"),
    ).toThrow();
    expect(() =>
      checkReleaseSignature(EXE, signed(EXE, GOOD, { algorithm: "Ed" }), key, "1.2.3"),
    ).toThrow();
    const text = Buffer.from(signed(EXE, GOOD), "base64").toString("utf8");
    const edited = b64(text.replace("version:1.2.3", "version:1.2.4"));
    expect(() => checkReleaseSignature(EXE, edited, key, "1.2.4")).toThrow();
  });
});

describe("SHA256SUMS and the release text", () => {
  test("sha256sum's text format, sorted, every name safe", () => {
    const a = sha256Of(Buffer.from("a"));
    const b = sha256Of(Buffer.from("b"));
    expect(
      sha256Sums([
        { name: "b.txt", sha256: b },
        { name: "AFKLink-1.2.3.exe", sha256: a },
      ]),
    ).toBe(`${a}  AFKLink-1.2.3.exe\n${b}  b.txt\n`);
    expect(() => sha256Sums([{ name: "x/y", sha256: a }])).toThrow(/cannot be listed/);
    expect(() => sha256Sums([{ name: "x\ny", sha256: a }])).toThrow(/cannot be listed/);
    expect(() => sha256Sums([{ name: "x", sha256: "ABC" }])).toThrow(/not a SHA-256/);
    expect(() =>
      sha256Sums([
        { name: "x", sha256: a },
        { name: "x", sha256: a },
      ]),
    ).toThrow(/twice/);
    expect(() => sha256Sums([])).toThrow(/empty/);
  });

  test("the CHANGELOG section first, then how to verify; an empty section is refused", () => {
    const body = releaseBody("- Fixed a thing.\n", "1.2.3", "afklink/afklink-pc");
    expect(body.startsWith("- Fixed a thing.\n")).toBe(true);
    expect(body).toContain("gh attestation verify AFKLink-1.2.3.exe --repo afklink/afklink-pc");
    expect(body).toContain("sha256sum -c SHA256SUMS");
    expect(() => releaseBody("  \n", "1.2.3", "afklink/afklink-pc")).toThrow(/empty/);
  });
});
