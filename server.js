'use strict';
require('dotenv').config();

const express = require('express');
const net = require('net');
const dns = require('dns').promises;
const fetch = require('node-fetch');
const whois = require('whois');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── DNS ENUMERATION ────────────────────────────────────────────────────────
async function dnsEnumerate(domain) {
  const types = ['A', 'MX', 'TXT', 'NS', 'CNAME'];
  const results = {};
  await Promise.allSettled(
    types.map(async (type) => {
      try {
        const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`;
        const res = await fetch(url, { timeout: 8000 });
        const data = await res.json();
        results[type] = data.Answer || data.Authority || [];
      } catch {
        results[type] = [];
      }
    })
  );
  return results;
}

// ─── PORT SCANNER ───────────────────────────────────────────────────────────
const TOP_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
  143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
  6379, 8080, 8443, 27017, 5432, 5000
];

function scanPort(host, port, timeout = 2500) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let status = 'closed';
    sock.setTimeout(timeout);
    sock.on('connect', () => { status = 'open'; sock.destroy(); });
    sock.on('timeout', () => { status = 'filtered'; sock.destroy(); });
    sock.on('error', (e) => {
      status = e.code === 'ECONNREFUSED' ? 'closed' : 'filtered';
      sock.destroy();
    });
    sock.on('close', () => resolve({ port, status }));
    sock.connect(port, host);
  });
}

async function portScan(host) {
  const results = await Promise.all(TOP_PORTS.map(p => scanPort(host, p)));
  return results;
}

// ─── WHOIS ──────────────────────────────────────────────────────────────────
function doWhois(domain) {
  return new Promise((resolve) => {
    whois.lookup(domain, { timeout: 10000 }, (err, data) => {
      if (err) return resolve({ raw: '', error: err.message });
      resolve({ raw: data || '' });
    });
  });
}

function parseWhoisFields(raw) {
  const fields = {};
  const patterns = {
    registrar: /registrar:\s*(.+)/i,
    created: /creat(?:ion|ed)[^\:]*:\s*(.+)/i,
    expires: /expir(?:y|ation|es)[^\:]*:\s*(.+)/i,
    updated: /updat(?:ed|e)[^\:]*:\s*(.+)/i,
    status: /status:\s*(.+)/i,
    nameservers: /name\s*server:\s*(.+)/gi,
    registrant: /registrant(?:\s+organization)?:\s*(.+)/i,
    privacy: /privacy|redacted|protected|masked/i,
  };

  for (const [key, rx] of Object.entries(patterns)) {
    if (key === 'nameservers') {
      const matches = [...raw.matchAll(rx)].map(m => m[1].trim());
      fields.nameservers = [...new Set(matches)];
    } else if (key === 'privacy') {
      fields.privacy = rx.test(raw);
    } else {
      const m = raw.match(rx);
      if (m) fields[key] = m[1].trim();
    }
  }
  return fields;
}

// ─── SUBDOMAIN DISCOVERY ────────────────────────────────────────────────────
async function subdomainDiscovery(domain) {
  try {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const res = await fetch(url, { timeout: 15000 });
    if (!res.ok) throw new Error(`crt.sh returned ${res.status}`);
    const data = await res.json();

    const subs = new Set();
    for (const entry of data) {
      const names = (entry.name_value || '').split('\n');
      for (const n of names) {
        const clean = n.replace(/^\*\./, '').trim().toLowerCase();
        if (clean.endsWith(domain) && clean !== domain) subs.add(clean);
      }
    }

    // Resolve each subdomain
    const list = [...subs].slice(0, 50);
    const resolved = await Promise.allSettled(
      list.map(async (sub) => {
        try {
          const addrs = await dns.resolve4(sub);
          return { subdomain: sub, ips: addrs, live: true };
        } catch {
          return { subdomain: sub, ips: [], live: false };
        }
      })
    );
    return resolved.map(r => r.value || r.reason);
  } catch (e) {
    return { error: e.message };
  }
}

// ─── BREACH CHECK ───────────────────────────────────────────────────────────
async function breachCheck(email) {
  const key = process.env.HIBP_API_KEY;
  if (!key || key === 'your_hibp_key_here') {
    return { error: 'No HIBP API key configured in .env' };
  }
  try {
    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      {
        headers: {
          'hibp-api-key': key,
          'User-Agent': 'THREATOPS-Dashboard',
        },
        timeout: 10000,
      }
    );
    if (res.status === 404) return { breaches: [], count: 0 };
    if (res.status === 401) return { error: 'Invalid HIBP API key' };
    if (!res.ok) return { error: `HIBP error: ${res.status}` };
    const breaches = await res.json();
    return { breaches, count: breaches.length };
  } catch (e) {
    return { error: e.message };
  }
}

// ─── TECH STACK DETECTION ───────────────────────────────────────────────────
async function techStackDetect(targetUrl) {
  try {
    const normalizedUrl = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
    const res = await fetch(normalizedUrl, {
      timeout: 10000,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; THREATOPS/1.0)' },
      redirect: 'follow',
    });

    const headers = {};
    res.headers.forEach((val, key) => { headers[key] = val; });
    const body = await res.text();

    const tech = [];

    // Server header
    if (headers['server']) tech.push({ name: headers['server'], category: 'Server', confidence: 'high' });

    // X-Powered-By
    if (headers['x-powered-by']) tech.push({ name: headers['x-powered-by'], category: 'Runtime', confidence: 'high' });

    // Cookies
    const setCookie = headers['set-cookie'] || '';
    if (/PHPSESSID/i.test(setCookie)) tech.push({ name: 'PHP', category: 'Language', confidence: 'high' });
    if (/JSESSIONID/i.test(setCookie)) tech.push({ name: 'Java/Servlet', category: 'Runtime', confidence: 'high' });
    if (/laravel_session|XSRF-TOKEN/i.test(setCookie)) tech.push({ name: 'Laravel', category: 'Framework', confidence: 'high' });
    if (/django_csrftoken|csrftoken/i.test(setCookie)) tech.push({ name: 'Django', category: 'Framework', confidence: 'high' });
    if (/wp-settings|wordpress/i.test(setCookie)) tech.push({ name: 'WordPress', category: 'CMS', confidence: 'high' });

    // HTML patterns
    const htmlPatterns = [
      { rx: /wp-content|wp-includes/i, name: 'WordPress', category: 'CMS' },
      { rx: /Drupal\.settings|\/sites\/default\/files/i, name: 'Drupal', category: 'CMS' },
      { rx: /Joomla!/i, name: 'Joomla', category: 'CMS' },
      { rx: /shopify/i, name: 'Shopify', category: 'Ecommerce' },
      { rx: /magento/i, name: 'Magento', category: 'Ecommerce' },
      { rx: /react\.(?:development|production|min)\.js|__REACT_DEVTOOLS/i, name: 'React', category: 'JS Framework' },
      { rx: /vue(?:\.min)?\.js|__vue__/i, name: 'Vue.js', category: 'JS Framework' },
      { rx: /angular(?:\.min)?\.js|ng-version/i, name: 'Angular', category: 'JS Framework' },
      { rx: /jquery(?:\.min)?\.js/i, name: 'jQuery', category: 'JS Library' },
      { rx: /bootstrap(?:\.min)?\.(?:css|js)/i, name: 'Bootstrap', category: 'CSS Framework' },
      { rx: /next\.js|__NEXT_DATA__/i, name: 'Next.js', category: 'Framework' },
      { rx: /nuxt/i, name: 'Nuxt.js', category: 'Framework' },
      { rx: /gatsby/i, name: 'Gatsby', category: 'Framework' },
      { rx: /<meta[^>]+generator[^>]+WordPress/i, name: 'WordPress', category: 'CMS' },
      { rx: /<meta[^>]+generator[^>]+Joomla/i, name: 'Joomla', category: 'CMS' },
      { rx: /<meta[^>]+generator[^>]+Drupal/i, name: 'Drupal', category: 'CMS' },
    ];

    for (const p of htmlPatterns) {
      if (p.rx.test(body)) {
        if (!tech.find(t => t.name === p.name)) {
          tech.push({ name: p.name, category: p.category, confidence: 'medium' });
        }
      }
    }

    // CDN detection
    if (headers['cf-ray']) tech.push({ name: 'Cloudflare', category: 'CDN', confidence: 'high' });
    if (headers['x-amz-cf-id']) tech.push({ name: 'AWS CloudFront', category: 'CDN', confidence: 'high' });
    if (headers['x-served-by'] && /fastly/i.test(headers['x-served-by'])) tech.push({ name: 'Fastly', category: 'CDN', confidence: 'high' });

    return { tech, statusCode: res.status, finalUrl: res.url };
  } catch (e) {
    return { error: e.message, tech: [] };
  }
}

// ─── HTTP HEADERS AUDIT ─────────────────────────────────────────────────────
const SECURITY_HEADERS = [
  {
    key: 'content-security-policy',
    name: 'Content-Security-Policy',
    weight: 30,
    description: 'Prevents XSS and injection attacks by defining allowed content sources',
  },
  {
    key: 'strict-transport-security',
    name: 'Strict-Transport-Security',
    weight: 25,
    description: 'Forces HTTPS connections, preventing SSL stripping attacks',
  },
  {
    key: 'x-frame-options',
    name: 'X-Frame-Options',
    weight: 15,
    description: 'Prevents clickjacking by controlling iframe embedding',
  },
  {
    key: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    weight: 10,
    description: 'Prevents MIME-type sniffing attacks',
  },
  {
    key: 'referrer-policy',
    name: 'Referrer-Policy',
    weight: 10,
    description: 'Controls referrer information sent with requests',
  },
  {
    key: 'permissions-policy',
    name: 'Permissions-Policy',
    weight: 10,
    description: 'Controls browser feature access (camera, mic, geolocation)',
  },
];

async function headersAudit(targetUrl) {
  try {
    const normalizedUrl = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
    const res = await fetch(normalizedUrl, {
      timeout: 10000,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; THREATOPS/1.0)' },
      redirect: 'follow',
    });

    const headers = {};
    res.headers.forEach((val, key) => { headers[key] = val; });

    let score = 0;
    const audit = SECURITY_HEADERS.map(h => {
      const val = headers[h.key];
      const present = !!val;
      if (present) score += h.weight;

      let grade = 'MISSING';
      if (present) {
        // Extra checks
        if (h.key === 'strict-transport-security') {
          const maxAge = parseInt((val.match(/max-age=(\d+)/) || [])[1] || '0');
          grade = maxAge >= 31536000 ? 'GOOD' : 'WEAK';
          if (maxAge < 31536000) score -= h.weight * 0.5;
        } else if (h.key === 'x-content-type-options') {
          grade = val.toLowerCase() === 'nosniff' ? 'GOOD' : 'WEAK';
        } else if (h.key === 'x-frame-options') {
          grade = /deny|sameorigin/i.test(val) ? 'GOOD' : 'WEAK';
        } else {
          grade = 'PRESENT';
        }
      }

      return { ...h, value: val || null, present, grade };
    });

    score = Math.max(0, Math.min(100, Math.round(score)));
    let letterGrade = 'F';
    if (score >= 90) letterGrade = 'A';
    else if (score >= 75) letterGrade = 'B';
    else if (score >= 60) letterGrade = 'C';
    else if (score >= 45) letterGrade = 'D';
    else if (score >= 25) letterGrade = 'E';

    return { audit, score, letterGrade, allHeaders: headers };
  } catch (e) {
    return { error: e.message, audit: [], score: 0, letterGrade: 'F' };
  }
}

// ─── INTELLIGENCE FEED GENERATOR ────────────────────────────────────────────
function generateFindings(results) {
  const findings = [];

  const push = (severity, title, detail, module) =>
    findings.push({ severity, title, detail, module, ts: new Date().toISOString() });

  // DNS findings
  const dns_res = results.dns;
  if (dns_res && !dns_res.error) {
    const aRecords = dns_res.A || [];
    if (aRecords.length === 0) push('medium', 'No A records found', 'Domain may not resolve or is behind proxy', 'DNS');
    if ((dns_res.TXT || []).some(r => r.data && /v=spf1/i.test(r.data) === false && /v=DMARC/i.test(r.data) === false)) {
      // no-op, just checking
    }
    const hasSPF = (dns_res.TXT || []).some(r => r.data && /v=spf1/i.test(r.data));
    const hasDMARC = (dns_res.TXT || []).some(r => r.data && /v=DMARC1/i.test(r.data));
    if (!hasSPF) push('medium', 'No SPF record', 'Missing SPF TXT record — domain vulnerable to email spoofing', 'DNS');
    if (!hasDMARC) push('medium', 'No DMARC record', 'Missing DMARC policy — no enforcement against spoofed email', 'DNS');
  }

  // Port findings
  const ports = results.ports;
  if (ports && Array.isArray(ports)) {
    const openPorts = ports.filter(p => p.status === 'open');
    const riskyOpen = openPorts.filter(p => [21, 23, 3306, 5432, 6379, 27017, 3389, 5900].includes(p.port));
    for (const p of riskyOpen) {
      const names = { 21: 'FTP', 23: 'Telnet', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB', 3389: 'RDP', 5900: 'VNC' };
      push('high', `Sensitive port ${p.port} (${names[p.port]}) is open`, `Exposed ${names[p.port]} service — potential unauthorized access vector`, 'Ports');
    }
    if (openPorts.some(p => p.port === 22)) push('info', 'SSH (port 22) open', 'SSH service detected — ensure key-based auth and no root login', 'Ports');
    if (openPorts.some(p => [8080, 8443].includes(p.port))) push('low', 'Non-standard HTTP port open', 'Development/admin web service may be exposed', 'Ports');
  }

  // WHOIS findings
  const whoisRes = results.whois;
  if (whoisRes && !whoisRes.error) {
    if (whoisRes.parsed && whoisRes.parsed.privacy) push('info', 'WHOIS privacy enabled', 'Registrant details are masked — normal for privacy protection', 'WHOIS');
    if (whoisRes.parsed && whoisRes.parsed.expires) {
      const exp = new Date(whoisRes.parsed.expires);
      const daysLeft = (exp - Date.now()) / 86400000;
      if (!isNaN(daysLeft) && daysLeft < 30) push('high', 'Domain expiring soon', `Domain expires in ~${Math.round(daysLeft)} days — risk of domain hijack`, 'WHOIS');
      else if (!isNaN(daysLeft) && daysLeft < 90) push('medium', 'Domain expires within 90 days', `Renew before ${whoisRes.parsed.expires}`, 'WHOIS');
    }
  }

  // Subdomains findings
  const subs = results.subdomains;
  if (subs && Array.isArray(subs)) {
    const live = subs.filter(s => s.live);
    if (live.length > 20) push('medium', `${live.length} live subdomains discovered`, 'Large attack surface — review each subdomain for exposure', 'Subdomains');
    const devLike = live.filter(s => /dev|staging|test|beta|admin|internal|vpn|api|jenkins|jira|gitlab|ci|uat/i.test(s.subdomain));
    for (const d of devLike.slice(0, 5)) {
      push('high', `Sensitive subdomain: ${d.subdomain}`, 'Dev/admin/internal subdomain publicly accessible', 'Subdomains');
    }
  }

  // Breach findings
  const breaches = results.breaches;
  if (breaches && !breaches.error) {
    if (breaches.count > 0) {
      push('high', `${breaches.count} breach(es) found`, `Email found in: ${(breaches.breaches || []).slice(0, 3).map(b => b.Name).join(', ')}`, 'Breach');
      const pastes = (breaches.breaches || []).filter(b => b.IsVerified === false);
      if (pastes.length) push('medium', 'Unverified breach data present', 'Some breach records are unverified — may indicate paste site exposure', 'Breach');
    } else {
      push('info', 'No breaches found', 'Email not found in HIBP database', 'Breach');
    }
  }

  // Tech stack findings
  const tech = results.tech;
  if (tech && tech.tech) {
    const cms = tech.tech.find(t => t.category === 'CMS');
    if (cms) push('medium', `CMS detected: ${cms.name}`, `${cms.name} installations should be kept updated to avoid known CVEs`, 'TechStack');
    const outdated = tech.tech.filter(t => /apache\/[12]\.|nginx\/1\.[0-9]\.|php\/[4567]\./i.test(t.name));
    for (const o of outdated) push('high', `Potentially outdated: ${o.name}`, 'Old server software version may have known vulnerabilities', 'TechStack');
  }

  // Headers findings
  const hdr = results.headers;
  if (hdr && hdr.audit) {
    const missing = hdr.audit.filter(h => !h.present);
    for (const m of missing) {
      const sev = m.weight >= 25 ? 'high' : m.weight >= 15 ? 'medium' : 'low';
      push(sev, `Missing: ${m.name}`, m.description, 'Headers');
    }
    if (hdr.score < 30) push('high', `Security headers score: ${hdr.letterGrade} (${hdr.score}/100)`, 'Very poor security header posture', 'Headers');
    else if (hdr.score < 60) push('medium', `Security headers score: ${hdr.letterGrade} (${hdr.score}/100)`, 'Moderate security header coverage — review missing headers', 'Headers');
  }

  // Sort: high → medium → low → info
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return findings;
}

// ─── SSE SCAN ENDPOINT ───────────────────────────────────────────────────────
app.get('/api/scan', async (req, res) => {
  const { target, email } = req.query;
  if (!target) return res.status(400).json({ error: 'target required' });

  // Extract domain from URL
  let domain = target;
  try {
    if (target.startsWith('http')) {
      domain = new URL(target).hostname;
    } else if (target.includes('/')) {
      domain = target.split('/')[0];
    }
  } catch {}

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  send('status', { msg: `Starting scan of ${domain}...`, ts: new Date().toISOString() });

  const allResults = {};

  // Run all scans in parallel, stream results as they complete
  const scanTasks = [
    (async () => {
      send('status', { msg: 'DNS: querying records...', module: 'dns' });
      try {
        const r = await dnsEnumerate(domain);
        allResults.dns = r;
        send('dns', r);
        send('status', { msg: 'DNS: complete', module: 'dns' });
      } catch (e) {
        allResults.dns = { error: e.message };
        send('dns', { error: e.message });
      }
    })(),

    (async () => {
      send('status', { msg: 'Ports: scanning top 25...', module: 'ports' });
      try {
        const r = await portScan(domain);
        allResults.ports = r;
        send('ports', r);
        send('status', { msg: 'Ports: complete', module: 'ports' });
      } catch (e) {
        allResults.ports = { error: e.message };
        send('ports', { error: e.message });
      }
    })(),

    (async () => {
      send('status', { msg: 'WHOIS: looking up registration...', module: 'whois' });
      try {
        const r = await doWhois(domain);
        const parsed = parseWhoisFields(r.raw || '');
        allResults.whois = { ...r, parsed };
        send('whois', allResults.whois);
        send('status', { msg: 'WHOIS: complete', module: 'whois' });
      } catch (e) {
        allResults.whois = { error: e.message };
        send('whois', { error: e.message });
      }
    })(),

    (async () => {
      send('status', { msg: 'Subdomains: querying crt.sh...', module: 'subdomains' });
      try {
        const r = await subdomainDiscovery(domain);
        allResults.subdomains = r;
        send('subdomains', r);
        send('status', { msg: 'Subdomains: complete', module: 'subdomains' });
      } catch (e) {
        allResults.subdomains = { error: e.message };
        send('subdomains', { error: e.message });
      }
    })(),

    (async () => {
      if (email) {
        send('status', { msg: 'Breach: checking HIBP...', module: 'breaches' });
        try {
          const r = await breachCheck(email);
          allResults.breaches = r;
          send('breaches', r);
          send('status', { msg: 'Breach: complete', module: 'breaches' });
        } catch (e) {
          allResults.breaches = { error: e.message };
          send('breaches', { error: e.message });
        }
      } else {
        send('breaches', { skipped: true, msg: 'No email provided' });
      }
    })(),

    (async () => {
      send('status', { msg: 'Tech: fingerprinting stack...', module: 'tech' });
      try {
        const r = await techStackDetect(target);
        allResults.tech = r;
        send('tech', r);
        send('status', { msg: 'Tech: complete', module: 'tech' });
      } catch (e) {
        allResults.tech = { error: e.message };
        send('tech', { error: e.message });
      }
    })(),

    (async () => {
      send('status', { msg: 'Headers: auditing security posture...', module: 'headers' });
      try {
        const r = await headersAudit(target);
        allResults.headers = r;
        send('headers', r);
        send('status', { msg: 'Headers: complete', module: 'headers' });
      } catch (e) {
        allResults.headers = { error: e.message };
        send('headers', { error: e.message });
      }
    })(),
  ];

  await Promise.allSettled(scanTasks);

  // Generate intelligence findings
  const findings = generateFindings(allResults);
  send('findings', findings);
  send('status', { msg: 'Scan complete.', done: true, ts: new Date().toISOString() });
  res.end();
});

// ─── START ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`THREATOPS running at http://localhost:${PORT}`);
});
