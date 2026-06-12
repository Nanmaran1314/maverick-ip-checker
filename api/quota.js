export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { vt, aipdb, ipqs } = req.query;
  const result = {};

  // ── VirusTotal ──────────────────────────────────────────────────────
  // GET /api/v3/users/{id} but we don't know the user id without auth
  // Instead, hit /users/me — VT returns quota info in the user object
  if (vt) {
    try {
      const r = await fetch('https://www.virustotal.com/api/v3/users/me', {
        headers: { 'x-apikey': vt },
        signal: AbortSignal.timeout(10000),
      });
      if (r.status === 401) {
        result.vt = { error: 'Invalid API key' };
      } else if (r.ok) {
        const data = await r.json();
        const quotas = data?.data?.attributes?.quotas || {};
        // api_requests_daily / hourly / monthly
        const daily   = quotas.api_requests_daily   || {};
        const hourly  = quotas.api_requests_hourly  || {};
        const monthly = quotas.api_requests_monthly || {};
        result.vt = {
          plan: data?.data?.attributes?.status || 'free',
          daily_used:      daily.used   ?? null,
          daily_limit:     daily.allowed ?? null,
          hourly_used:     hourly.used   ?? null,
          hourly_limit:    hourly.allowed ?? null,
          monthly_used:    monthly.used   ?? null,
          monthly_limit:   monthly.allowed ?? null,
        };
      } else {
        result.vt = { error: `HTTP ${r.status}` };
      }
    } catch (e) {
      result.vt = { error: e.message };
    }
  }

  // ── AbuseIPDB ────────────────────────────────────────────────────────
  // The /check endpoint returns X-RateLimit-* headers AND the response
  // body has no quota info — but /api/v2/report uses RateLimit headers.
  // Best approach: hit /api/v2/check on a well-known benign IP (1.1.1.1)
  // and read the response headers.
  if (aipdb) {
    try {
      const r = await fetch(
        'https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=1',
        {
          headers: { 'Key': aipdb, 'Accept': 'application/json' },
          signal: AbortSignal.timeout(10000),
        }
      );
      if (r.status === 401 || r.status === 403) {
        result.aipdb = { error: 'Invalid API key' };
      } else if (r.ok) {
        // AbuseIPDB returns quota in response headers
        const limit     = r.headers.get('X-RateLimit-Limit');
        const remaining = r.headers.get('X-RateLimit-Remaining');
        const reset     = r.headers.get('X-RateLimit-Reset');  // unix timestamp
        result.aipdb = {
          daily_limit:     limit     ? parseInt(limit)     : 1000,
          daily_remaining: remaining ? parseInt(remaining) : null,
          daily_used:      (limit && remaining)
            ? parseInt(limit) - parseInt(remaining)
            : null,
          resets_at: reset
            ? new Date(parseInt(reset) * 1000).toISOString().split('T')[0]
            : null,
        };
      } else {
        result.aipdb = { error: `HTTP ${r.status}` };
      }
    } catch (e) {
      result.aipdb = { error: e.message };
    }
  }

  // ── IPQualityScore ───────────────────────────────────────────────────
  // IPQS has an /account endpoint that returns credits_used / credits_remaining
  if (ipqs) {
    try {
      const r = await fetch(
        `https://ipqualityscore.com/api/json/account/${encodeURIComponent(ipqs)}`,
        { signal: AbortSignal.timeout(10000) }
      );
      if (!r.ok) {
        result.ipqs = { error: `HTTP ${r.status}` };
      } else {
        const d = await r.json();
        if (!d.success) {
          result.ipqs = { error: d.message || 'API error' };
        } else {
          result.ipqs = {
            plan:               d.account_type || 'free',
            credits_used:       d.credits_used       ?? null,
            credits_remaining:  d.credits_remaining  ?? null,
            daily_limit:        d.total_credits       ?? null,
            monthly_limit:      d.monthly_credits     ?? null,
            // older API versions expose these directly
            lookups_allowed:    d.allowed             ?? null,
            lookups_used:       d.used                ?? null,
          };
        }
      }
    } catch (e) {
      result.ipqs = { error: e.message };
    }
  }

  return res.status(200).json(result);
}
