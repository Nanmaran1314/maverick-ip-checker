export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { vt: vtKey, aipdb: aipdbKey, ipqs: ipqsKey } = req.query;
  const result = {};

  // ── VirusTotal ──────────────────────────────────────────────────
  if (vtKey) {
    try {
      const r = await fetch('https://www.virustotal.com/api/v3/users/me', {
        headers: { 'x-apikey': vtKey },
        signal: AbortSignal.timeout(12000),
      });
      if (r.ok) {
        const d = await r.json();
        const q     = d?.data?.attributes?.quotas || {};
        const daily = q.api_requests_daily || {};
        const monthly = q.api_requests_monthly || {};
        result.vt = {
          daily_used:     daily.used    ?? null,
          daily_limit:    daily.allowed ?? null,
          monthly_used:   monthly.used  ?? null,
          monthly_limit:  monthly.allowed ?? null,
          plan:           d?.data?.attributes?.status || 'free',
        };
      } else if (r.status === 401) {
        result.vt = { error: 'Invalid API key (401)' };
      } else {
        result.vt = { error: `VT HTTP ${r.status}` };
      }
    } catch (e) {
      result.vt = { error: e.message };
    }
  }

  // ── AbuseIPDB ───────────────────────────────────────────────────
  if (aipdbKey) {
    try {
      // AbuseIPDB doesn't have a dedicated quota endpoint on free tier.
      // We check by making a test call to /api/v2/check with a well-known IP
      // and reading the X-RateLimit-* headers.
      const r = await fetch(
        'https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=1',
        {
          headers: { 'Key': aipdbKey, 'Accept': 'application/json' },
          signal: AbortSignal.timeout(12000),
        }
      );
      if (r.status === 401 || r.status === 403) {
        result.aipdb = { error: 'Invalid API key' };
      } else if (r.ok) {
        // Parse rate-limit headers if present
        const limit     = r.headers.get('X-RateLimit-Limit')     || '1000';
        const remaining = r.headers.get('X-RateLimit-Remaining') || null;
        const reset     = r.headers.get('X-RateLimit-Reset')     || null;

        const dailyLimit = parseInt(limit, 10);
        const dailyRemaining = remaining !== null ? parseInt(remaining, 10) : null;
        const dailyUsed = dailyRemaining !== null ? dailyLimit - dailyRemaining : null;

        result.aipdb = {
          daily_limit:     dailyLimit,
          daily_used:      dailyUsed,
          daily_remaining: dailyRemaining,
          resets_on:       reset ? new Date(parseInt(reset, 10) * 1000).toISOString().split('T')[0] : null,
          plan:            dailyLimit >= 10000 ? 'premium' : 'free',
        };
      } else {
        result.aipdb = { error: `AbuseIPDB HTTP ${r.status}` };
      }
    } catch (e) {
      result.aipdb = { error: e.message };
    }
  }

  // ── IPQualityScore ──────────────────────────────────────────────
  if (ipqsKey) {
    try {
      // IPQS account endpoint returns credit balance
      const r = await fetch(
        `https://ipqualityscore.com/api/json/account/${encodeURIComponent(ipqsKey)}`,
        { signal: AbortSignal.timeout(12000) }
      );
      if (r.ok) {
        const d = await r.json();
        if (d.success) {
          result.ipqs = {
            credits_used:      d.credits_used      ?? null,
            credits_remaining: d.credits_remaining ?? null,
            daily_limit:       d.total_credits     ?? null,
            plan:              d.account_type       || 'free',
          };
        } else {
          result.ipqs = { error: d.message || 'IPQS account error' };
        }
      } else if (r.status === 401) {
        result.ipqs = { error: 'Invalid API key (401)' };
      } else {
        result.ipqs = { error: `IPQS HTTP ${r.status}` };
      }
    } catch (e) {
      result.ipqs = { error: e.message };
    }
  }

  return res.status(200).json(result);
}
