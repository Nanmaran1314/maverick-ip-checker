export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { ip, key } = req.query;
  if (!ip || !key) return res.status(400).json({ error: 'Missing ip or key param' });

  try {
    // IPQS puts the API key in the URL path — no custom headers needed
    const url = `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(key)}/${encodeURIComponent(ip)}?strictness=1&allow_public_access_points=true&lighter_penalties=true&fast=false`;

    const upstream = await fetch(url, {
      signal: AbortSignal.timeout(15000),
    });

    if (upstream.status === 400) return res.status(400).json({ error: 'Bad request — check your IPQS API key format' });
    if (upstream.status === 401) return res.status(401).json({ error: 'Invalid IPQS API key' });
    if (!upstream.ok) return res.status(upstream.status).json({ error: `IPQS HTTP ${upstream.status}` });

    const data = await upstream.json();

    // IPQS returns success:false for errors (e.g. insufficient credits)
    if (!data.success) {
      return res.status(402).json({ error: data.message || 'IPQS error — check your plan credits' });
    }

    return res.status(200).json({
      fraud_score:     data.fraud_score,
      proxy:           data.proxy,
      vpn:             data.vpn,
      tor:             data.tor,
      bot_status:      data.bot_status,
      recent_abuse:    data.recent_abuse,
      abuse_velocity:  data.abuse_velocity,
      isp:             data.ISP,
      organization:    data.organization,
      connection_type: data.connection_type,
      country_code:    data.country_code,
      city:            data.city,
      mobile:          data.mobile,
    });
  } catch (e) {
    return res.status(500).json({ error: 'Proxy error: ' + e.message });
  }
}
