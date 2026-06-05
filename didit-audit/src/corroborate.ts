/**
 * Cross-corroboration of the core facts of a verification — WHO (identity),
 * WHERE (place), WHEN (time) — from several independent methods/tools, so no
 * single source is trusted alone.
 *
 * For each fact we collect multiple Claims, then compute a consensus and flag
 * any disagreement. The result is embedded in the audit payload, so it is itself
 * hash-chained, anchored, and replicated by the rest of the module.
 *
 * Methods used out of the box come from Didit's own modules (document, face,
 * liveness, AML, IP, phone). Add more tools — e.g. extra geo-IP providers via
 * GEOIP_URLS — to raise the corroboration count with no code change.
 *
 * NOTE: field paths below follow Didit's typical decision shape; adjust the
 * `pick()` path lists to match your exact response.
 */

export type Dimension = 'identity' | 'location' | 'time';

export interface Claim {
  dimension: Dimension;
  source: string; // method/tool id, e.g. 'didit.document', 'geoip:ipapi.co'
  value: string | null; // normalized: 'pass'/'fail' | ISO-3166 country | ISO-8601 time
  detail?: Record<string, unknown>;
}

export interface DimensionConsensus {
  value: string | null;
  agree: boolean;
  sources: number; // how many methods produced a usable claim
  method: string; // how consensus was derived
  dissenting?: string[]; // sources that disagreed with the consensus
}

export interface Corroboration {
  claims: Claim[];
  consensus: Record<Dimension, DimensionConsensus>;
  flags: string[];
}

export interface CorroborateOptions {
  identityQuorum?: number; // min independent 'pass' signals (default 2)
  timeToleranceMs?: number; // max spread between time claims (default 5 min)
}

function pick(obj: unknown, paths: string[]): unknown {
  for (const p of paths) {
    const v = p.split('.').reduce<unknown>((o, k) => (o == null ? undefined : (o as Record<string, unknown>)[k]), obj);
    if (v != null) return v;
  }
  return undefined;
}

/** Normalize a country signal to an upper-case ISO code (best effort). */
function countryCode(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim().toUpperCase();
  return s.length >= 2 && s.length <= 3 ? s : s || null;
}

/** Interpret a module result as a pass/fail signal. */
function passFail(v: unknown): 'pass' | 'fail' | null {
  if (v == null) return null;
  const s = String(v).toLowerCase();
  if (['approved', 'pass', 'passed', 'clear', 'success', 'true', 'verified', 'match'].includes(s)) return 'pass';
  if (['declined', 'fail', 'failed', 'hit', 'rejected', 'false', 'no_match'].includes(s)) return 'fail';
  return null;
}

function csv(value: string | undefined): string[] {
  return (value ?? '').split(',').map((s) => s.trim()).filter(Boolean);
}

/** Extract identity/location/time claims from a Didit decision. */
export function diditClaims(event: Record<string, unknown>): Claim[] {
  const claims: Claim[] = [];
  const add = (dimension: Dimension, source: string, value: string | null, detail?: Record<string, unknown>) => {
    if (value != null) claims.push({ dimension, source, value, detail });
  };

  // WHO — independent identity methods.
  add('identity', 'didit.document', passFail(pick(event, ['id_verification.status', 'document.status'])));
  add('identity', 'didit.face', passFail(pick(event, ['face_match.status', 'face.status'])));
  add('identity', 'didit.liveness', passFail(pick(event, ['liveness.status'])));
  add('identity', 'didit.aml', passFail(pick(event, ['aml.status', 'aml_screening.status'])));

  // WHERE — independent location signals.
  add('location', 'didit.ip', countryCode(pick(event, ['ip_analysis.country', 'ip.country', 'device.ip_country'])), {
    ip: pick(event, ['ip_analysis.ip', 'ip.address']),
  });
  add('location', 'didit.document', countryCode(pick(event, ['id_verification.issuing_country', 'id_verification.document_country', 'document.country'])));
  add('location', 'didit.phone', countryCode(pick(event, ['phone.country', 'phone_number.country'])));

  // WHEN — Didit's asserted time plus our own receipt time.
  const diditTime = pick(event, ['timestamp', 'created_at', 'decision_time']);
  if (typeof diditTime === 'string') add('time', 'didit.timestamp', new Date(diditTime).toISOString());
  add('time', 'server.clock', new Date().toISOString());

  return claims;
}

/** Optional external geo-IP tools (one Claim per GEOIP_URLS template). */
async function geoIpClaims(ip: unknown): Promise<Claim[]> {
  if (typeof ip !== 'string' || !ip) return [];
  const out: Claim[] = [];
  for (const tmpl of csv(process.env.GEOIP_URLS)) {
    try {
      const url = tmpl.replace('{ip}', encodeURIComponent(ip));
      const res = await fetch(url);
      if (!res.ok) continue;
      const body = (await res.json()) as Record<string, unknown>;
      const cc = countryCode(pick(body, ['country_code', 'countryCode', 'country']));
      const host = (() => {
        try {
          return new URL(tmpl.replace('{ip}', '0')).host;
        } catch {
          return 'geoip';
        }
      })();
      if (cc) out.push({ dimension: 'location', source: `geoip:${host}`, value: cc, detail: { ip } });
    } catch {
      /* a flaky corroborator must not break the others */
    }
  }
  return out;
}

function median(nums: number[]): number {
  const s = [...nums].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2);
}

/** Compute consensus + disagreement flags over a set of claims. */
export function evaluate(claims: Claim[], opts: CorroborateOptions = {}): Corroboration {
  const identityQuorum = opts.identityQuorum ?? Number(process.env.CORROBORATE_IDENTITY_QUORUM ?? 2);
  const timeToleranceMs = opts.timeToleranceMs ?? Number(process.env.CORROBORATE_TIME_TOLERANCE_MS ?? 300_000);
  const flags: string[] = [];
  const by = (d: Dimension) => claims.filter((c) => c.dimension === d);

  // IDENTITY — quorum of independent 'pass' signals, no 'fail'.
  const id = by('identity');
  const passes = id.filter((c) => c.value === 'pass');
  const fails = id.filter((c) => c.value === 'fail');
  const idAgree = fails.length === 0 && passes.length >= identityQuorum;
  if (fails.length) flags.push(`identity:dissent(${fails.map((c) => c.source).join(',')})`);
  else if (passes.length < identityQuorum) flags.push(`identity:insufficient(${passes.length}/${identityQuorum})`);
  const identity: DimensionConsensus = {
    value: idAgree ? 'verified' : 'review',
    agree: idAgree,
    sources: id.length,
    method: `quorum>=${identityQuorum}`,
    dissenting: fails.map((c) => c.source),
  };

  // LOCATION — majority country across independent signals.
  const loc = by('location').filter((c) => c.value);
  const tally = new Map<string, number>();
  for (const c of loc) tally.set(c.value!, (tally.get(c.value!) ?? 0) + 1);
  const top = [...tally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
  const dissenting = loc.filter((c) => c.value !== top).map((c) => c.source);
  const locAgree = loc.length >= 2 && dissenting.length === 0;
  if (loc.length < 2) flags.push(`location:insufficient(${loc.length})`);
  else if (dissenting.length) flags.push(`location:disagreement(${[...tally.entries()].map(([k, n]) => `${k}:${n}`).join(',')})`);
  const location: DimensionConsensus = {
    value: top,
    agree: locAgree,
    sources: loc.length,
    method: 'majority',
    dissenting,
  };

  // TIME — claims must agree within tolerance; consensus = median.
  const times = by('time')
    .map((c) => ({ source: c.source, ms: c.value ? Date.parse(c.value) : NaN }))
    .filter((t) => !Number.isNaN(t.ms));
  let time: DimensionConsensus;
  if (times.length >= 2) {
    const spread = Math.max(...times.map((t) => t.ms)) - Math.min(...times.map((t) => t.ms));
    const agree = spread <= timeToleranceMs;
    if (!agree) flags.push(`time:skew=${Math.round(spread / 1000)}s`);
    time = {
      value: new Date(median(times.map((t) => t.ms))).toISOString(),
      agree,
      sources: times.length,
      method: `median±${Math.round(timeToleranceMs / 1000)}s`,
    };
  } else {
    flags.push(`time:insufficient(${times.length})`);
    time = { value: times[0]?.ms ? new Date(times[0].ms).toISOString() : null, agree: false, sources: times.length, method: 'single' };
  }

  return { claims, consensus: { identity, location, time }, flags };
}

/** Collect claims from every configured method and evaluate consensus. */
export async function corroborate(
  event: Record<string, unknown>,
  opts: CorroborateOptions = {},
): Promise<Corroboration> {
  const claims = diditClaims(event);
  const ip = pick(event, ['ip_analysis.ip', 'ip.address', 'device.ip']);
  claims.push(...(await geoIpClaims(ip)));
  return evaluate(claims, opts);
}
