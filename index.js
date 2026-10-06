// BugScan - pemindai website nyata (tanpa dependensi, butuh Node.js >= 18)
const http = require('http');
const dns = require('dns').promises, net = require('net'), tls = require('tls');
const PORT = process.env.PORT || 3000;
const UA = 'BugScan/1.0 (+pemindai-website)';

// ---------- Perlindungan SSRF ----------
function isPrivateIP(ip) {
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80');
}
async function assertPublicHost(host) {
  const addrs = await dns.lookup(host, { all: true });
  if (!addrs.length || addrs.some(a => isPrivateIP(a.address)))
    throw new Error('Alamat ditolak: host mengarah ke jaringan privat/internal.');
}

async function readLimited(res, limit) {
  const reader = res.body.getReader(); const chunks = []; let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length; chunks.push(value);
    if (size >= limit) { try { await reader.cancel(); } catch {} break; }
  }
  return Buffer.concat(chunks).toString('utf8');
}

// fetch dengan redirect manual, tiap lompatan divalidasi
async function safeFetch(url, { method = 'GET', limit = 1.5e6, maxRedirects = 6, follow = true } = {}) {
  const chain = []; let cur = url; const t0 = Date.now();
  for (let i = 0; i <= maxRedirects; i++) {
    const u = new URL(cur);
    if (!/^https?:$/.test(u.protocol)) throw new Error('Hanya http/https yang didukung.');
    await assertPublicHost(u.hostname);
    const res = await fetch(cur, {
      method, redirect: 'manual', signal: AbortSignal.timeout(12000),
      headers: { 'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8' }
    });
    chain.push({ url: cur, status: res.status });
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      if (!follow) return { res, body: '', chain, ms: Date.now() - t0, finalUrl: cur };
      cur = new URL(res.headers.get('location'), cur).href;
      try { await res.body?.cancel(); } catch {}
      continue;
    }
    const body = method === 'HEAD' ? '' : await readLimited(res, limit);
    return { res, body, chain, ms: Date.now() - t0, finalUrl: cur };
  }
  throw new Error('Terlalu banyak redirect (kemungkinan redirect loop).');
}

function tlsInfo(host) {
  return new Promise(resolve => {
    const s = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 8000 }, () => {
      const c = s.getPeerCertificate();
      resolve({ valid_to: c.valid_to, authorized: s.authorized, error: s.authorizationError ? String(s.authorizationError) : null, protocol: s.getProtocol() });
      s.end();
    });
    s.on('error', () => resolve(null)); s.on('timeout', () => { s.destroy(); resolve(null); });
  });
}

// ---------- Pemindaian ----------
const SENSITIVE = [
  ['/.env', b => /^[A-Z][A-Z0-9_]{2,}=.+/m.test(b), 'high', 'File .env terbuka (berisi kredensial/rahasia aplikasi)'],
  ['/.git/HEAD', b => /^ref: refs\//.test(b), 'high', 'Repositori .git terbuka (source code bisa diunduh)'],
  ['/wp-config.php.bak', b => /DB_PASSWORD/.test(b), 'high', 'Backup wp-config terbuka'],
  ['/backup.sql', b => /CREATE TABLE|INSERT INTO/i.test(b), 'high', 'Dump database terbuka'],
  ['/.htpasswd', b => /^[^:\s]+:(\$|\{SHA\})/m.test(b), 'high', 'File .htpasswd terbuka'],
  ['/phpinfo.php', b => /PHP Version|phpinfo\(\)/.test(b), 'medium', 'phpinfo() terbuka (membocorkan konfigurasi server)'],
  ['/server-status', b => /Apache Server Status/.test(b), 'medium', 'Halaman server-status Apache terbuka'],
  ['/.DS_Store', b => b.startsWith('\u0000\u0000\u0000\u0001Bud1'), 'low', 'File .DS_Store terbuka (membocorkan struktur direktori)'],
];

async function scan(input) {
  let raw = input.trim();
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  const target = new URL(raw);
  const F = []; const add = (sev, cat, title, detail, fix) => F.push({ sev, cat, title, detail, fix });

  const main = await safeFetch(target.href);
  const { res, body, chain, ms, finalUrl } = main;
  const fu = new URL(finalUrl); const isHttps = fu.protocol === 'https:';
  const h = n => res.headers.get(n);
  const ct = h('content-type') || '';
  const meta = { finalUrl, status: res.status, ms, size: Buffer.byteLength(body), server: h('server') || null, redirects: chain.length - 1, contentType: ct };

  // Ketersediaan & performa
  if (res.status >= 500) add('high', 'Ketersediaan', `Server mengembalikan error ${res.status}`, 'Halaman utama gagal dimuat dengan benar.', 'Periksa log server dan aplikasi.');
  else if (res.status >= 400) add('high', 'Ketersediaan', `Halaman mengembalikan ${res.status}`, 'URL tidak dapat diakses secara normal.', 'Pastikan URL benar dan halaman tersedia untuk publik.');
  if (chain.length > 3) add('low', 'Performa', `Rantai redirect panjang (${chain.length - 1} lompatan)`, chain.map(c => c.status + ' ' + c.url).join(' → '), 'Kurangi redirect agar halaman dimuat lebih cepat.');
  if (ms > 3000) add('medium', 'Performa', `Respons lambat (${ms} ms)`, 'Waktu hingga isi halaman terunduh lebih dari 3 detik.', 'Aktifkan cache/CDN dan optimalkan backend.');
  if (!/gzip|br|deflate|zstd/.test(h('content-encoding') || '') && meta.size > 20000) add('low', 'Performa', 'Kompresi tidak aktif', 'Respons HTML tidak dikompres.', 'Aktifkan gzip atau brotli di server.');

  // HTTPS & sertifikat
  if (!isHttps) add('high', 'HTTPS', 'Situs tidak menggunakan HTTPS', 'Data pengunjung dikirim tanpa enkripsi.', 'Pasang sertifikat TLS (mis. Let\'s Encrypt) dan paksa HTTPS.');
  else {
    const info = await tlsInfo(fu.hostname);
    if (info) {
      const days = Math.floor((new Date(info.valid_to) - Date.now()) / 864e5);
      meta.certDays = days;
      if (!info.authorized) add('high', 'HTTPS', 'Sertifikat TLS tidak tepercaya', info.error || 'Validasi sertifikat gagal.', 'Gunakan sertifikat dari CA tepercaya dengan rantai lengkap.');
      if (days < 0) add('high', 'HTTPS', 'Sertifikat TLS sudah kedaluwarsa', `Kedaluwarsa ${-days} hari lalu.`, 'Perbarui sertifikat segera.');
      else if (days < 14) add('medium', 'HTTPS', `Sertifikat kedaluwarsa ${days} hari lagi`, 'Berisiko mati jika tidak diperbarui.', 'Aktifkan perpanjangan otomatis.');
      if (['TLSv1', 'TLSv1.1'].includes(info.protocol)) add('medium', 'HTTPS', `Protokol TLS usang (${info.protocol})`, 'Versi ini dianggap tidak aman.', 'Aktifkan minimal TLS 1.2.');
    }
    try {
      const r = await safeFetch('http://' + fu.host + '/', { follow: false, limit: 1 });
      const loc = r.res.headers.get('location') || '';
      if (!(r.res.status >= 300 && r.res.status < 400 && loc.startsWith('https://')))
        add('medium', 'HTTPS', 'HTTP tidak dialihkan ke HTTPS', 'Versi http:// masih bisa diakses tanpa enkripsi.', 'Tambahkan redirect 301 dari HTTP ke HTTPS.');
    } catch {}
  }

  // Header keamanan
  const hdr = [
    ['content-security-policy', 'medium', 'Content-Security-Policy tidak ada', 'Tanpa CSP, serangan XSS lebih mudah dieksploitasi.', 'Tambahkan header CSP yang membatasi sumber skrip.'],
    ['x-content-type-options', 'low', 'X-Content-Type-Options tidak ada', 'Browser dapat menebak tipe konten (MIME sniffing).', 'Tambahkan "X-Content-Type-Options: nosniff".'],
    ['referrer-policy', 'low', 'Referrer-Policy tidak ada', 'URL halaman bisa bocor ke situs lain lewat Referer.', 'Tambahkan "Referrer-Policy: strict-origin-when-cross-origin".'],
    ['permissions-policy', 'info', 'Permissions-Policy tidak ada', 'Fitur browser (kamera, lokasi, dll.) tidak dibatasi.', 'Tambahkan Permissions-Policy sesuai kebutuhan.'],
  ];
  if (isHttps && !h('strict-transport-security')) add('medium', 'Header', 'HSTS tidak ada', 'Browser tidak dipaksa memakai HTTPS (rawan downgrade).', 'Tambahkan "Strict-Transport-Security: max-age=31536000; includeSubDomains".');
  if (!h('x-frame-options') && !/frame-ancestors/i.test(h('content-security-policy') || '')) add('medium', 'Header', 'Perlindungan clickjacking tidak ada', 'Situs bisa dibingkai di situs lain.', 'Tambahkan "X-Frame-Options: DENY" atau CSP frame-ancestors.');
  for (const [n, s, t, d, f] of hdr) if (!h(n)) add(s, 'Header', t, d, f);
  const xpb = h('x-powered-by'); if (xpb) add('low', 'Kebocoran info', `X-Powered-By: ${xpb}`, 'Teknologi server terlihat oleh penyerang.', 'Hapus header X-Powered-By.');
  const sv = h('server'); if (sv && /\d+\.\d+/.test(sv)) add('low', 'Kebocoran info', `Versi server terlihat: ${sv}`, 'Versi spesifik mempermudah pencarian celah yang diketahui.', 'Sembunyikan versi (server_tokens off / ServerTokens Prod).');
  if (h('access-control-allow-origin') === '*' && /true/i.test(h('access-control-allow-credentials') || '')) add('high', 'CORS', 'CORS wildcard dengan credentials', 'Origin mana pun diizinkan mengirim permintaan berkredensial.', 'Whitelist origin tertentu.');
  else if (h('access-control-allow-origin') === '*') add('info', 'CORS', 'CORS terbuka untuk semua origin', 'Access-Control-Allow-Origin: *', 'Pastikan memang tidak ada data sensitif di endpoint ini.');

  // Cookie
  for (const c of (res.headers.getSetCookie?.() || [])) {
    const name = c.split('=')[0]; const miss = [];
    if (isHttps && !/;\s*secure/i.test(c)) miss.push('Secure');
    if (!/;\s*httponly/i.test(c)) miss.push('HttpOnly');
    if (!/;\s*samesite/i.test(c)) miss.push('SameSite');
    if (miss.length) add(/sess|auth|token|login/i.test(name) ? 'medium' : 'low', 'Cookie', `Cookie "${name}" tanpa atribut ${miss.join(', ')}`, 'Cookie rentan dicuri atau dikirim lintas situs.', 'Set atribut Secure, HttpOnly, dan SameSite pada cookie.');
  }

  // Analisis HTML
  if (/html/i.test(ct) && body) {
    const tag = (re) => [...body.matchAll(re)];
    if (!/^\s*<!doctype html/i.test(body)) add('low', 'HTML', 'DOCTYPE tidak ada', 'Browser bisa masuk quirks mode.', 'Tambahkan <!DOCTYPE html> di baris pertama.');
    const title = (body.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1]?.trim();
    if (!title) add('medium', 'SEO', 'Tag <title> kosong/tidak ada', 'Penting untuk SEO dan aksesibilitas.', 'Tambahkan <title> yang deskriptif.');
    else if (title.length > 70) add('info', 'SEO', `Judul terlalu panjang (${title.length} karakter)`, 'Akan terpotong di hasil pencarian.', 'Persingkat di bawah 60 karakter.');
    if (!/<meta[^>]+name=["']description["'][^>]*content=["'][^"']+/i.test(body)) add('low', 'SEO', 'Meta description tidak ada', 'Mesin pencari akan memilih cuplikan sendiri.', 'Tambahkan <meta name="description">.');
    if (!/<meta[^>]+name=["']viewport["']/i.test(body)) add('medium', 'Responsif', 'Meta viewport tidak ada', 'Tampilan di ponsel kemungkinan rusak.', 'Tambahkan <meta name="viewport" content="width=device-width, initial-scale=1">.');
    if (!/<html[^>]+lang=/i.test(body)) add('low', 'Aksesibilitas', 'Atribut lang pada <html> tidak ada', 'Pembaca layar tidak tahu bahasa halaman.', 'Tambahkan lang="id" (atau bahasa yang sesuai).');
    const h1 = tag(/<h1[\s>]/gi).length;
    if (h1 === 0) add('low', 'SEO', 'Tidak ada <h1>', 'Struktur heading tidak jelas.', 'Gunakan satu <h1> per halaman.');
    else if (h1 > 1) add('info', 'SEO', `Ada ${h1} elemen <h1>`, 'Disarankan hanya satu.', 'Gunakan <h2> untuk sub-judul.');
    const noAlt = tag(/<img\b(?![^>]*\balt=)[^>]*>/gi).length;
    if (noAlt) add('medium', 'Aksesibilitas', `${noAlt} gambar tanpa atribut alt`, 'Gambar tidak terbaca oleh pembaca layar.', 'Tambahkan alt pada setiap gambar.');
    if (isHttps) {
      const mixed = [...new Set(tag(/(?:src|href|action)=["'](http:\/\/[^"']+)/gi).map(m => m[1]))].filter(u => !/^http:\/\/(www\.w3\.org)/.test(u));
      const active = mixed.filter(u => /\.(js|css)(\?|$)/i.test(u));
      if (active.length) add('high', 'Mixed content', `${active.length} skrip/CSS dimuat lewat HTTP`, active.slice(0, 4).join('\n'), 'Ganti semua sumber menjadi https://.');
      else if (mixed.length) add('medium', 'Mixed content', `${mixed.length} sumber dimuat lewat HTTP`, mixed.slice(0, 4).join('\n'), 'Ganti menjadi https://.');
    }
    const blank = tag(/<a\b[^>]*target=["']_blank["'][^>]*>/gi).filter(m => !/rel=["'][^"']*noopener/i.test(m[0])).length;
    if (blank) add('low', 'Keamanan', `${blank} tautan target="_blank" tanpa rel="noopener"`, 'Halaman tujuan dapat mengakses window.opener.', 'Tambahkan rel="noopener noreferrer".');
    for (const m of tag(/<form\b[^>]*>[\s\S]*?<\/form>/gi)) {
      if (/type=["']password["']/i.test(m[0])) {
        const act = (m[0].match(/action=["']([^"']*)/i) || [])[1] || '';
        if (/^http:\/\//i.test(act) || (!isHttps)) add('high', 'Keamanan', 'Form password dikirim tanpa HTTPS', 'Kata sandi dapat disadap di jaringan.', 'Kirim form hanya lewat HTTPS.');
        if (!/autocomplete=/i.test(m[0])) add('info', 'Keamanan', 'Form login tanpa atribut autocomplete', 'Atur perilaku pengisian otomatis browser.', 'Gunakan autocomplete="current-password".');
      }
    }
    const inl = tag(/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi).length;
    if (inl > 8) add('info', 'Performa', `${inl} skrip inline`, 'Menyulitkan penerapan CSP ketat dan caching.', 'Pindahkan ke file eksternal.');
    if (/\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9a-zA-Z]{24,}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)/.test(body)) add('high', 'Kebocoran info', 'Kunci rahasia terlihat di HTML', 'Pola API key/private key ditemukan di sumber halaman.', 'Cabut kunci tersebut segera dan pindahkan ke backend.');
    if (/(Warning|Fatal error|Notice):.*? in .*? on line \d+|Traceback \(most recent call last\)|at [\w.$]+\([\w./\\-]+:\d+:\d+\)|SQLSTATE\[|You have an error in your SQL syntax/i.test(body)) add('high', 'Error aplikasi', 'Pesan error/stack trace tampil di halaman', 'Detail internal aplikasi terekspos ke pengunjung.', 'Matikan debug/display_errors di produksi.');

    // Cek tautan rusak (maks. 20 tautan, same-origin + eksternal)
    const links = [...new Set(tag(/<a\b[^>]*href=["']([^"'#]+)["']/gi).map(m => m[1]).filter(l => !/^(mailto:|tel:|javascript:|data:)/i.test(l)).map(l => { try { return new URL(l, finalUrl).href; } catch { return null; } }).filter(Boolean))].slice(0, 20);
    meta.linksChecked = links.length;
    const broken = []; let idx = 0;
    await Promise.all(Array.from({ length: 5 }, async () => {
      while (idx < links.length) {
        const l = links[idx++];
        try {
          let r = await safeFetch(l, { method: 'HEAD', limit: 1 });
          if (r.res.status === 405 || r.res.status === 403) r = await safeFetch(l, { limit: 1 });
          if (r.res.status === 404 || r.res.status === 410 || r.res.status >= 500) broken.push(`${r.res.status} ${l}`);
        } catch (e) { broken.push(`gagal ${l}`); }
      }
    }));
    if (broken.length) add('medium', 'Tautan rusak', `${broken.length} dari ${links.length} tautan bermasalah`, broken.slice(0, 8).join('\n'), 'Perbaiki atau hapus tautan yang rusak.');
  }

  // File sensitif
  const origin = fu.origin; let probed = 0;
  await Promise.all(SENSITIVE.map(async ([p, test, sev, title]) => {
    try {
      const r = await safeFetch(origin + p, { limit: 20000, follow: false });
      probed++;
      if (r.res.status === 200 && test(r.body)) add(sev, 'File sensitif', title, origin + p, `Blokir akses ke ${p} di konfigurasi web server.`);
    } catch {}
  }));
  meta.probed = SENSITIVE.length;
  try {
    const r = await safeFetch(origin + '/robots.txt', { limit: 20000, follow: false });
    if (r.res.status !== 200 || /<html/i.test(r.body)) add('info', 'SEO', 'robots.txt tidak ditemukan', 'Crawler tidak mendapat panduan.', 'Buat file robots.txt.');
  } catch {}

  const w = { high: 15, medium: 7, low: 2, info: 0 };
  const score = Math.max(0, 100 - F.reduce((s, f) => s + w[f.sev], 0));
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  F.sort((a, b) => order[a.sev] - order[b.sev]);
  return { target: target.href, scannedAt: new Date().toISOString(), score, meta, findings: F };
}

// ---------- Antarmuka (HTML) ----------
const HTML = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BugScan – Cari bug website dari URL</title>
<style>
:root{--bg:#eef1f4;--ink:#14212b;--mut:#5b6b78;--card:#fff;--line:#d5dce2;--acc:#0b5f73;
--high:#b3261e;--med:#b26a00;--low:#4b6a00;--info:#4a5b68}
@media(prefers-color-scheme:dark){:root{--bg:#10171c;--ink:#e6edf1;--mut:#93a4b0;--card:#18222a;--line:#2a3944;--acc:#58c4dc;
--high:#ff8a80;--med:#ffb74d;--low:#c5e17a;--info:#9fb2bf}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 "Segoe UI",system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:48px 20px 80px}
h1{font:700 clamp(2rem,6vw,3.2rem)/1.05 Georgia,"Times New Roman",serif;letter-spacing:-.02em;margin:0 0 10px}
.sub{color:var(--mut);max-width:60ch;margin:0 0 28px}
form{display:flex;gap:8px;flex-wrap:wrap}
input[type=text]{flex:1 1 280px;font:inherit;padding:14px 16px;border:2px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink)}
input[type=text]:focus{outline:3px solid var(--acc);outline-offset:1px;border-color:var(--acc)}
button{font:inherit;font-weight:600;padding:14px 26px;border:0;border-radius:8px;background:var(--acc);color:#fff;cursor:pointer}
@media(prefers-color-scheme:dark){button{color:#08242c}}
button:focus-visible{outline:3px solid var(--ink);outline-offset:2px}button:disabled{opacity:.6;cursor:wait}
.consent{display:flex;gap:8px;align-items:flex-start;margin:14px 0 0;color:var(--mut);font-size:.9rem}
.consent input{margin-top:4px}
#status{margin:28px 0;color:var(--mut)}#status.err{color:var(--high);font-weight:600}
.sum{display:grid;grid-template-columns:auto 1fr;gap:24px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:22px;margin-bottom:22px}
.score{font:700 3.6rem/1 Georgia,serif}.score small{font-size:1rem;color:var(--mut);font-family:inherit;font-weight:400}
.sum dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px 18px;margin:0}
.sum dt{font-size:.8rem;color:var(--mut)}.sum dd{margin:0;font-weight:600;overflow-wrap:anywhere}
.counts{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 18px}
.chip{border:1px solid currentColor;border-radius:99px;padding:3px 12px;font-size:.88rem;font-weight:600}
.f{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--c);border-radius:8px;margin:0 0 10px}
.f summary{cursor:pointer;padding:13px 16px;font-weight:600;list-style:none;display:flex;gap:10px;align-items:baseline}
.f summary::-webkit-details-marker{display:none}
.f summary:focus-visible{outline:3px solid var(--acc);outline-offset:-3px}
.sev{color:var(--c);font-size:.82rem;min-width:62px}.cat{margin-left:auto;color:var(--mut);font-weight:400;font-size:.82rem;white-space:nowrap}
.f .b{padding:0 16px 14px 88px;color:var(--ink)}.f pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--bg);padding:8px 10px;border-radius:6px;font-size:.85rem;margin:6px 0}
.f .fix{color:var(--mut)}.f .fix b{color:var(--ink)}
.high{--c:var(--high)}.medium{--c:var(--med)}.low{--c:var(--low)}.info{--c:var(--info)}
.note{color:var(--mut);font-size:.85rem;margin-top:30px;border-top:1px solid var(--line);padding-top:16px}
@media(max-width:560px){.sum{grid-template-columns:1fr}.f .b{padding-left:16px}.f summary{flex-wrap:wrap}.cat{margin-left:0}}
</style>
</head>
<body>
<main>
<h1>Temukan bug website hanya dengan URL</h1>
<p class="sub">BugScan mengunduh situs secara langsung lalu memeriksa keamanan, HTTPS, header, cookie, file sensitif, tautan rusak, SEO, dan aksesibilitas.</p>
<form id="f">
  <input type="text" id="u" placeholder="contoh.com atau https://contoh.com" autocomplete="off" required aria-label="URL website">
  <button id="go">Pindai website</button>
  <label class="consent"><input type="checkbox" id="ok" required> Saya pemilik situs ini atau sudah punya izin untuk memindainya.</label>
</form>
<div id="status" role="status" aria-live="polite"></div>
<section id="out" hidden></section>
<p class="note">Pemindaian bersifat pasif dan ringan (permintaan GET/HEAD biasa). Hasilnya bukan pengganti audit keamanan profesional; bug yang butuh browser (error JavaScript di console, tampilan visual) tidak terdeteksi.</p>
</main>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const L={high:'Kritis',medium:'Sedang',low:'Rendah',info:'Info'};
$('f').addEventListener('submit',async e=>{
  e.preventDefault();const st=$('status'),out=$('out'),btn=$('go');
  btn.disabled=true;out.hidden=true;st.className='';st.textContent='Memindai… biasanya 10–30 detik.';
  try{
    const r=await fetch('/api?url='+encodeURIComponent($('u').value));
    const d=await r.json();if(!r.ok)throw new Error(d.error||'Gagal memindai');
    render(d);st.textContent='';
  }catch(err){st.className='err';st.textContent=err.message}
  btn.disabled=false;
});
function render(d){
  const c={high:0,medium:0,low:0,info:0};d.findings.forEach(f=>c[f.sev]++);
  const m=d.meta;
  $('out').innerHTML=\`
  <div class="sum"><div class="score" style="color:var(--\${d.score>=80?'low':d.score>=50?'med':'high'})">\${d.score}<small> / 100</small></div>
  <dl><div><dt>URL akhir</dt><dd>\${esc(m.finalUrl)}</dd></div><div><dt>Status HTTP</dt><dd>\${m.status}</dd></div>
  <div><dt>Waktu respons</dt><dd>\${m.ms} ms</dd></div><div><dt>Ukuran HTML</dt><dd>\${(m.size/1024).toFixed(1)} KB</dd></div>
  <div><dt>Server</dt><dd>\${esc(m.server||'tersembunyi')}</dd></div>
  \${m.certDays!=null?\`<div><dt>Sertifikat</dt><dd>\${m.certDays} hari lagi</dd></div>\`:''}
  <div><dt>Tautan diperiksa</dt><dd>\${m.linksChecked||0}</dd></div></dl></div>
  <div class="counts">\${Object.keys(c).map(k=>\`<span class="chip \${k}" style="color:var(--c)">\${L[k]}: \${c[k]}</span>\`).join('')}</div>
  \${d.findings.length?d.findings.map((f,i)=>\`<details class="f \${f.sev}" \${i<3&&f.sev==='high'?'open':''}>
   <summary><span class="sev">\${L[f.sev]}</span><span>\${esc(f.title)}</span><span class="cat">\${esc(f.cat)}</span></summary>
   <div class="b"><pre>\${esc(f.detail)}</pre><div class="fix"><b>Perbaikan:</b> \${esc(f.fix)}</div></div></details>\`).join('')
   :'<p>Tidak ada masalah yang terdeteksi pada pemeriksaan ini.</p>'}\`;
  $('out').hidden=false;
}
</script>
</body>
</html>
`;

// ---------- Handler: jalan di Vercel (/api) maupun lokal ----------
const hits = new Map();
function limited(ip) {
  const now = Date.now(), arr = (hits.get(ip) || []).filter(t => now - t < 60000);
  arr.push(now); hits.set(ip, arr); return arr.length > 8;
}
async function handler(req, res) {
  const u = new URL(req.url, 'http://x');
  const json = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); };
  if (!u.searchParams.has('url')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(HTML);
  }
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'x').split(',')[0];
  if (limited(ip)) return json(429, { error: 'Terlalu banyak permintaan. Coba lagi dalam semenit.' });
  const target = u.searchParams.get('url');
  if (!target || target.length > 2000) return json(400, { error: 'Parameter url wajib diisi.' });
  try { json(200, await scan(target)); }
  catch (e) {
    const m = e.cause?.code === 'ENOTFOUND' || e.code === 'ENOTFOUND' ? 'Domain tidak ditemukan.'
      : e.name === 'TimeoutError' ? 'Situs tidak merespons (timeout).' : e.message;
    json(400, { error: m });
  }
}

module.exports = handler;
module.exports.config = { maxDuration: 60 };
if (require.main === module)
  http.createServer(handler).listen(PORT, () => console.log(`BugScan berjalan di http://localhost:${PORT}`));
