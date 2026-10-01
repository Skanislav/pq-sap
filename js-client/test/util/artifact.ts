import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Resolve a Foundry artifact across forge versions/profiles.
//
// Forge names artifacts `<Contract>.json` when a contract compiles in exactly one
// profile, but `<Contract>.<profile>.json` per profile when compilation restrictions
// (via_ir / optimizer overrides) give it different bytecode per profile. e2e suites
// must not depend on which shape a given forge build happens to produce, so try
// the un-suffixed name first, then any profile suffix, preferring `default`.
export function artifactFrom(outDir: string, rel: string) {
  // rel is `Dir/Contract.json` or `Dir/Contract.Profile.json` style
  const base = `${outDir}/${rel}`;
  if (existsSync(base)) return JSON.parse(readFileSync(base, 'utf8'));

  const slash = rel.lastIndexOf('/');
  const dir = rel.slice(0, slash);
  const file = rel.slice(slash + 1);
  const dot = file.indexOf('.');
  const stem = dot === -1 ? file : file.slice(0, dot);

  // exact stem with any single suffix, `default` preferred
  const out = `${outDir}/${dir}`;
  if (!existsSync(out)) {
    throw new Error(`contracts not built (missing ${out}); run npm run build-contracts`);
  }
  const candidates = existsSync(`${out}/${stem}.default.json`)
    ? [`${out}/${stem}.default.json`]
    : (readdirSync(out) as string[]).filter((f) => f.startsWith(`${stem}.`) && f.endsWith('.json'));
  if (candidates.length === 0) {
    throw new Error(`no artifact for ${rel} under ${out}`);
  }
  return JSON.parse(readFileSync(candidates[0], 'utf8'));
}