export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'Missing ip param' });

  try {
    const upstream = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,asname,proxy,hosting,query`,
      { signal: AbortSignal.timeout(10000) }
    );

    if (!upstream.ok) return res.status(upstream.status).json({ error: `ip-api HTTP ${upstream.status}` });

    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Proxy error: ' + e.message });
  }
}
