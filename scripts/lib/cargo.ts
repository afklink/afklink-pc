/**
 * The two Cargo files a release touches: the version in Cargo.toml's `[workspace.package]`, and
 * the check that Cargo.lock followed it and nothing else.
 */
import { Failure } from "./common";

/** `[workspace.package] version = "<from>"` → `"<to>"`; exactly one such line, or a Failure. */
export function bumpCargoToml(text: string, from: string, to: string): string {
  let section = "";
  let hits = 0;
  const out = text.split("\n").map((line) => {
    const header = /^\s*\[+([^\]]+)\]+\s*(?:#.*)?$/.exec(line);
    if (header !== null) {
      section = (header[1] ?? "").trim();
      return line;
    }
    const m = /^(\s*version\s*=\s*")([^"]*)(".*)$/.exec(line);
    if (section !== "workspace.package" || m === null) return line;
    hits++;
    if (m[2] !== from) {
      throw new Failure(
        `Cargo.toml: [workspace.package] version = "${m[2]}", а cargo видит ${from}`,
      );
    }
    return `${m[1]}${to}${m[3]}`;
  });
  if (hits !== 1) {
    throw new Failure(`Cargo.toml: строк version в [workspace.package] — ${hits}, а нужна одна`);
  }
  return out.join("\n");
}

/** Cargo.lock's `[[package]]` blocks: the text before the first, and each block's own text. */
function lockBlocks(text: string): { preamble: string; blocks: string[] } {
  const [preamble = "", ...blocks] = text.replace(/\r\n/g, "\n").split("\n[[package]]\n");
  return { preamble, blocks };
}

/**
 * That `cargo update --workspace` changed only the workspace's own `version` lines, `from` → `to`:
 * every registry package, every dependency list and every checksum exactly as before. The
 * workspace's packages are the blocks without a `source`.
 */
export function checkLockChange(before: string, after: string, from: string, to: string): void {
  const a = lockBlocks(before);
  const b = lockBlocks(after);
  const problems: string[] = [];
  if (a.preamble !== b.preamble) problems.push("изменилось начало файла");
  if (a.blocks.length !== b.blocks.length) {
    problems.push(`пакетов было ${a.blocks.length}, стало ${b.blocks.length}`);
  }
  const ours = (block: string) => !/^source = /m.test(block);
  const want = new Set(
    a.blocks.map((block) =>
      ours(block) ? block.replace(`\nversion = "${from}"`, `\nversion = "${to}"`) : block,
    ),
  );
  for (const block of b.blocks) {
    if (!want.has(block)) problems.push(`неожиданно: ${block.split("\n").slice(0, 2).join(" ")}`);
  }
  if (problems.length > 0) {
    throw new Failure(
      "Cargo.lock после cargo update --workspace изменился не только в версиях workspace:\n  " +
        problems.slice(0, 10).join("\n  "),
    );
  }
}
