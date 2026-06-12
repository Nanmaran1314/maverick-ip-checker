export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { ip, key } = req.query;
  if (!ip || !key) return res.status(400).json({ error: 'Missing ip or key param' });

  try {
    const upstream = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: { 'Key': key, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(15000),
      }
    );

    if (upstream.status === 401 || upstream.status === 403)
      return res.status(upstream.status).json({ error: 'Invalid API key' });
    if (upstream.status === 429)
      return res.status(429).json({ error: 'Daily limit reached (1,000/day on free tier)' });
    if (!upstream.ok)
      return res.status(upstream.status).json({ error: `AbuseIPDB HTTP ${upstream.status}` });

    const json = await upstream.json();
    if (!json?.data) return res.status(500).json({ error: json?.errors?.[0]?.detail || 'No data returned' });

    const d = json.data;
    return res.status(200).json({
      abuseConfidenceScore: d.abuseConfidenceScore,
      totalReports:         d.totalReports,
      numDistinctUsers:     d.numDistinctUsers,
      lastReportedAt:       d.lastReportedAt ? d.lastReportedAt.split('T')[0] : null,
      isWhitelisted:        d.isWhitelisted,
      isTor:                d.isTor,
      usageType:            d.usageType,
      isp:                  d.isp,
      domain:               d.domain,
      countryCode:          d.countryCode,
    });
  } catch (e) {
    return res.status(500).json({ error: 'Proxy error: ' + e.message });
  }
}
