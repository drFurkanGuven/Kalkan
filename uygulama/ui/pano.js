// Kalkan geniş görünüm (pano). Panelle aynı `sor` API'sini kullanır.
const tauri = window.__TAURI__;
const sor = tauri ? (istek) => tauri.core.invoke("sor", { istek }) : (istek) => window.sahteSor(istek);

const $ = (id) => document.getElementById(id);
const sonCizim = new WeakMap();
const ciz = (el, html) => { if (sonCizim.get(el) !== html) { el.innerHTML = html; sonCizim.set(el, html); } };
let gunlukSuzgec = "";

const kacis = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const sayi = (n) => Number(n || 0).toLocaleString("tr-TR");
function bayt(n) {
  n = Number(n || 0); const b = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1000 && i < b.length - 1) { n /= 1000; i++; }
  return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)).toString().replace(".", ",") + " " + b[i];
}
function once(us) {
  const sn = Math.max(0, (Date.now() - us / 1000) / 1000);
  if (sn < 60) return "az önce"; if (sn < 3600) return Math.floor(sn / 60) + " dk önce";
  if (sn < 86400) return Math.floor(sn / 3600) + " sa önce"; return Math.floor(sn / 86400) + " gün önce";
}
const saat = (us) => new Date(us / 1000).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
const saatsn = (us) => new Date(us / 1000).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const tarih = (us) => new Date(us / 1000).toLocaleString("tr-TR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
function seviye(r) { return r >= 10 ? ["yuksek", "Yüksek"] : r >= 3 ? ["orta", "Orta"] : ["dusuk", "Düşük"]; }

const SIMGE_KALKAN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:28px;height:28px"><path d="M12 2.5 4 5.2v6.1c0 4.9 3.3 8.6 8 10.2 4.7-1.6 8-5.3 8-10.2V5.2z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>';

// ---------- üst durum ----------
function ustCiz(durum, uyarilar) {
  const rozet = $("rozet"), alt = $("ust-alt");
  if (!durum) { rozet.className = "rozet"; rozet.textContent = "Kapalı"; alt.textContent = "Servis çalışmıyor"; return; }
  if (durum.mod_ === "ogrenme") {
    rozet.className = "rozet ogren"; rozet.textContent = "Öğreniyor";
    alt.textContent = `Ağını tanıyor · ${durum.arayuz || "-"}`;
  } else if (uyarilar.length) {
    rozet.className = "rozet kotu"; rozet.textContent = `${uyarilar.length} uyarı`;
    alt.textContent = `İzleniyor · ${durum.arayuz || "-"}`;
  } else {
    rozet.className = "rozet iyi"; rozet.textContent = "Güvende";
    alt.textContent = `İzleniyor · ${durum.arayuz || "-"}`;
  }
}

// ---------- sayılar ----------
function sayilarCiz(durum, seri, uyarilar, cihazlar) {
  const akis = seri.reduce((t, d) => t + d.akis, 0);
  const veri = seri.reduce((t, d) => t + d.bayt, 0);
  const anomali = uyarilar.length;
  const kutu = (deg, ad, vurgu) => `<div class="sayi${vurgu ? " vurgu" : ""}"><b>${deg}</b><span>${ad}</span></div>`;
  ciz($("sayilar"),
    kutu(durum ? sayi(akis) : "–", "akış · 1 saat")
    + kutu(durum ? bayt(veri) : "–", "veri · 1 saat")
    + kutu(durum ? sayi(durum.acik_akis) : "–", "açık bağlantı")
    + kutu(durum ? sayi(anomali) : "–", "uyarı · 24 saat", anomali > 0)
    + kutu(durum ? sayi(cihazlar.length) : "–", "ağdaki cihaz"));
}

// ---------- grafik ----------
function grafikCiz(seri) {
  const svg = $("grafik");
  const simdiDk = Math.floor(Date.now() / 60000);
  const harita = new Map(seri.map((d) => [Math.floor(d.dakika_us / 60e6), d]));
  const enCok = Math.max(1, ...seri.map((d) => d.akis));
  const gen = 800 / 60;
  let html = '<line class="cizgi" x1="0" y1="159" x2="800" y2="159"/>';
  for (let i = 0; i < 60; i++) {
    const d = harita.get(simdiDk - 59 + i);
    const y = d ? Math.max(3, Math.sqrt(d.akis / enCok) * 150) : 1;
    html += `<rect x="${(i * gen + 1).toFixed(1)}" y="${(160 - y).toFixed(1)}" width="${(gen - 2).toFixed(1)}" height="${y.toFixed(1)}" rx="1.5"${d && d.anomali ? ' class="anomali"' : ""}><title>${saat((simdiDk - 59 + i) * 60e6)} · ${d ? d.akis : 0} akış${d && d.anomali ? ", " + d.anomali + " anomali" : ""}</title></rect>`;
  }
  svg.innerHTML = html;
  $("grafik-ozet").textContent = seri.length ? `en yoğun dakika: ${sayi(enCok)} akış` : "";
}

// ---------- canlı akışlar ----------
let oncekiAkis = new Set();
function akislarCiz(akislar) {
  const kutu = $("akislar");
  $("akis-ozet").textContent = akislar.length ? `son ${akislar.length}` : "";
  if (!akislar.length) { ciz(kutu, '<div class="bos">Henüz bağlantı yok</div>'); return; }
  const yeniSet = new Set(akislar.map((a) => `${a.zaman_us}|${a.hedef_ip}|${a.hedef_port}`));
  const html = akislar.map((a) => {
    const anah = `${a.zaman_us}|${a.hedef_ip}|${a.hedef_port}`;
    const yeni = !oncekiAkis.has(anah) && oncekiAkis.size > 0;
    const adli = a.surec || a.alan_adi;
    const ust = adli ? `${a.surec ? `<b>${kacis(a.surec)}</b>` : ""}${a.surec && a.alan_adi ? " → " : ""}${a.alan_adi ? kacis(a.alan_adi) : ""}` : `${kacis(a.kaynak_ip)} → ${kacis(a.hedef_ip)}`;
    return `<div class="satir${a.anomali ? " anomali" : ""}${yeni ? " yeni" : ""}">
      <time>${saatsn(a.zaman_us)}</time>
      <span class="ad">${ust}<small>${kacis(a.hedef_ip)}:${a.hedef_port} ${kacis(a.protokol)}</small></span>
      <span class="boyut">${bayt(a.bayt)}</span></div>`;
  }).join("");
  ciz(kutu, html);
  oncekiAkis = yeniSet;
}

// ---------- uyarılar (araç ipuçlarıyla) ----------
function uyarilarCiz(uyarilar) {
  const kutu = $("uyarilar");
  $("uyari-ozet").textContent = uyarilar.length ? `${uyarilar.length} etkin` : "";
  if (!uyarilar.length) { ciz(kutu, `<div class="bos">${SIMGE_KALKAN}<p>Alışılmadık bir şey yok</p></div>`); return; }
  ciz(kutu, uyarilar.map((u) => {
    const [sev, sevAd] = seviye(u.risk);
    const hedef = u.hedefler.join(", ") + (u.hedef_sayisi > u.hedefler.length ? ` +${u.hedef_sayisi - u.hedefler.length}` : "");
    return `<div class="uyari ${sev}">
      <div class="uyari-ust"><h3>${kacis(u.tur)}</h3><time>${once(u.son_us)}</time></div>
      <p>${kacis(u.aciklama)}</p>
      ${u.surec || u.alan_adi ? `<div class="yol">${u.surec ? kacis(u.surec) + " → " : ""}${kacis(u.alan_adi || hedef)}</div>` : `<div class="yol">${kacis(u.kaynak)} → ${kacis(hedef)}</div>`}
      ${u.arac_ipucu ? `<div class="arac"><b>Muhtemel araç:</b> <code>${kacis(u.arac_ipucu)}</code><span>${kacis(u.arac_aciklama || "")}</span></div>` : ""}
      <div style="margin-top:7px"><span class="seviye ${sev}">${sevAd}</span></div>
    </div>`;
  }).join(""));
}

// ---------- cihazlar ----------
function cihazlarCiz(cihazlar, durum) {
  const kutu = $("cihazlar");
  $("cihaz-ozet").textContent = cihazlar.length ? `${cihazlar.length} cihaz` : "";
  const gecitIp = durum && durum.arp && durum.arp.gecit_ip;
  if (!cihazlar.length) { ciz(kutu, '<div class="bos">Henüz cihaz görülmedi</div>'); return; }
  ciz(kutu, cihazlar.map((c) => {
    const baslik = c.ad || c.uretici || (c.rastgele_mac ? "Telefon / tablet (gizli MAC)" : "Bilinmeyen cihaz");
    const alt = [c.ipler.join(", ") || "IP yok", c.mac, c.ad && c.uretici ? c.uretici : ""].filter(Boolean).join(" · ");
    const et = [
      c.rol === "gecit" ? '<span class="etiket gecit">Ağ geçidi</span>' : "",
      c.rol === "bu_mac" ? '<span class="etiket bu">Bu Mac</span>' : "",
      gecitIp && c.rol !== "gecit" && c.ipler.includes(gecitIp) ? '<span class="etiket taklit">Ağ geçidi taklidi!</span>' : "",
      c.rastgele_mac ? '<span class="etiket">Gizli MAC</span>' : "",
    ].join("");
    return `<div class="cihaz${c.rol ? " " + c.rol : ""}"><div><b>${kacis(baslik)}</b>${et}<span class="alt">${kacis(alt)}</span></div><time>${once(c.son_us)}</time></div>`;
  }).join(""));
}

// ---------- günlük ----------
const KATEGORI = { "": "Tümü", uyari: "Uyarılar", kural: "Kurallar", ag: "Ağ", sistem: "Sistem" };
function gunlukCiz(olaylar) {
  ciz($("gunluk-suzgec"), Object.entries(KATEGORI).map(([k, ad]) =>
    `<button class="${k === gunlukSuzgec ? "secili" : ""}" data-kategori="${k}">${ad}</button>`).join(""));
  const kutu = $("gunluk");
  if (!olaylar.length) { ciz(kutu, '<div class="bos">Bu kategoride olay yok</div>'); return; }
  ciz(kutu, olaylar.map((o) =>
    `<div class="olay ${o.seviye}" title="${kacis(o.ayrinti ? JSON.stringify(o.ayrinti) : "")}">
      <time>${saatsn(o.zaman_us)}</time><span class="kat">${KATEGORI[o.kategori] || o.kategori}</span>
      <span class="mesaj">${kacis(o.mesaj.replace(/^[⚠⛔🥷]️?\s*/u, ""))}</span></div>`).join(""));
}

$("gunluk-suzgec").addEventListener("click", (e) => {
  const b = e.target.closest("[data-kategori]");
  if (!b) return;
  gunlukSuzgec = b.dataset.kategori;
  yenile();
});

// ---------- yenileme ----------
let yenileniyor = false;
async function yenile() {
  if (yenileniyor) return;
  yenileniyor = true;
  try {
    let durum = null;
    try { durum = await sor({ komut: "durum" }); } catch { durum = null; }
    let uyarilar = [], seri = [], akislar = [], cihazlar = [], olaylar = [];
    if (durum) {
      [uyarilar, seri, akislar, cihazlar, olaylar] = await Promise.all([
        sor({ komut: "uyarilar", saat: 24 }).catch(() => []),
        sor({ komut: "zaman_serisi", dakika: 60 }).catch(() => []),
        sor({ komut: "akislar", adet: 60 }).catch(() => []),
        sor({ komut: "cihazlar" }).catch(() => []),
        sor({ komut: "olaylar", saat: 24, kategori: gunlukSuzgec, adet: 200 }).catch(() => []),
      ]);
    }
    ustCiz(durum, uyarilar);
    sayilarCiz(durum, seri, uyarilar, cihazlar);
    grafikCiz(seri);
    akislarCiz(akislar);
    uyarilarCiz(uyarilar);
    cihazlarCiz(cihazlar, durum);
    gunlukCiz(olaylar);
  } finally {
    yenileniyor = false;
  }
}

if (tauri) {
  tauri.event.listen("yenile", yenile);
  tauri.event.listen("panel_acildi", yenile);
}
setInterval(yenile, 5000);
yenile();
