export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { ip, key } = req.query;
  if (!ip || !key) return res.status(400).json({ error: 'Missing ip or key param' });

  try {
    const upstream = await fetch(
      `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
      {
        headers: { 'x-apikey': key },
        signal: AbortSignal.timeout(15000),
      }
    );

    if (upstream.status === 401) return res.status(401).json({ error: 'Invalid API key (401)' });
    if (upstream.status === 429) return res.status(429).json({ error: 'Rate limit hit — wait 1 min (4/min free tier)' });
    if (!upstream.ok) return res.status(upstream.status).json({ error: `VT HTTP ${upstream.status}` });

    const data = await upstream.json();
    const stats   = data?.data?.attributes?.last_analysis_stats || {};
    const engines = data?.data?.attributes?.last_analysis_results || {};
    const malEngines = Object.entries(engines)
      .filter(([, v]) => v.category === 'malicious')
      .map(([k]) => k);

    return res.status(200).json({
      malicious:  stats.malicious  || 0,
      suspicious: stats.suspicious || 0,
      harmless:   stats.harmless   || 0,
      undetected: stats.undetected || 0,
      total:      Object.keys(engines).length,
      country:    data?.data?.attributes?.country,
      asOwner:    data?.data?.attributes?.as_owner,
      reputation: data?.data?.attributes?.reputation,
      network:    data?.data?.attributes?.network,
      malEngines: malEngines.slice(0, 8),
    });
  } catch (e) {
    return res.status(500).json({ error: 'Proxy error: ' + e.message });
  }
}
