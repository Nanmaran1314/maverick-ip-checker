export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { ip, key } = req.query;
  if (!ip || !key) return res.status(400).json({ error: 'Missing ip or key param' });

  try {
    const upstream = await fetch(
      `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(key)}/${encodeURIComponent(ip)}?strictness=1&allow_public_access_points=true`,
      { signal: AbortSignal.timeout(15000) }
    );

    if (!upstream.ok)
      return res.status(upstream.status).json({ error: `IPQS HTTP ${upstream.status}` });

    const d = await upstream.json();
    if (!d.success) return res.status(400).json({ error: d.message });

    return res.status(200).json({
      fraud_score:     d.fraud_score,
      proxy:           d.proxy,
      vpn:             d.vpn,
      tor:             d.tor,
      bot_status:      d.bot_status,
      recent_abuse:    d.recent_abuse,
      abuse_velocity:  d.abuse_velocity,
      isp:             d.ISP,
      organization:    d.organization,
      connection_type: d.connection_type,
    });
  } catch (e) {
    return res.status(500).json({ error: 'Proxy error: ' + e.message });
  }
}
