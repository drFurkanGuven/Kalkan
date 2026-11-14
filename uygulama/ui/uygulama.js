// Kalkan paneli. Servisle Rust tarafındaki `sor` komutu üzerinden konuşur.
// Tauri dışında (tarayıcı önizlemesi) ornek.js'teki sahte veriyi kullanır.

const tauri = window.__TAURI__;
const sor = tauri
  ? (istek) => tauri.core.invoke("sor", { istek })
  : (istek) => window.sahteSor(istek);

const $ = (id) => document.getElementById(id);
// İçerik değişmediyse DOM'a dokunma: 5 sn'lik yenileme tıklamaları yutmasın
const sonCizim = new WeakMap();
const ciz = (el, html) => { if (sonCizim.get(el) !== html) { el.innerHTML = html; sonCizim.set(el, html); } };
let seciliSekme = "uyarilar";
const acikAyrintilar = new Set();
let sonUyarilar = [];
let sonDurum = null;
let engelSecimi = null; // süre seçimi açık olan uyarının anahtarı

// ---------- biçimlendirme ----------

const SIMGE = {
  kalkan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 4 5.2v6.1c0 4.9 3.3 8.6 8 10.2 4.7-1.6 8-5.3 8-10.2V5.2z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>',
  uyari: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 4 5.2v6.1c0 4.9 3.3 8.6 8 10.2 4.7-1.6 8-5.3 8-10.2V5.2z"/><path d="M12 8v4.5M12 16h.01"/></svg>',
  ara: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>',
  ag: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M5 16v-3h14v3M12 8v5"/></svg>',
  gizli: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18"/><path d="M10.6 5.1A10 10 0 0 1 12 5c5 0 9 4.5 10 7a13 13 0 0 1-2.6 3.6M6.6 6.6C4.3 8 2.7 10.2 2 12c1 2.5 5 7 10 7 1.6 0 3.1-.4 4.4-1.1"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>',
  engel: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="m5.7 5.7 12.6 12.6"/></svg>',
  ogren: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>',
  kapali: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M8 12h8"/></svg>',
};

const kacis = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const sayi = (n) => Number(n || 0).toLocaleString("tr-TR");

function bayt(n) {
  n = Number(n || 0);
  const birim = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < birim.length - 1) { n /= 1000; i++; }
  return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)).toString().replace(".", ",") + " " + birim[i];
}

function once(us) {
  const sn = Math.max(0, (Date.now() - us / 1000) / 1000);
  if (sn < 60) return "az önce";
  if (sn < 3600) return Math.floor(sn / 60) + " dk önce";
  if (sn < 86400) return Math.floor(sn / 3600) + " sa önce";
  return Math.floor(sn / 86400) + " gün önce";
}

const saat = (us) => new Date(us / 1000).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
const tarih = (us) => new Date(us / 1000).toLocaleString("tr-TR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

// Engellenecek "karşı taraf": bağlantının bu Mac'e ait olmayan ucu
function karsiTaraf(u, durum) {
  const yerel = new Set((durum && durum.yerel_ipler) || []);
  if (!yerel.has(u.kaynak)) return u.kaynak;
  if (u.hedef_sayisi === 1 && u.hedefler[0] && !yerel.has(u.hedefler[0])) return u.hedefler[0];
  return null; // bu Mac birçok yere bağlanmış: tek bir adres engellemek anlamsız
}

function kalanSure(bitis_us) {
  if (!bitis_us) return "kalıcı";
  const dk = Math.max(0, Math.round((bitis_us / 1000 - Date.now()) / 60000));
  if (dk < 60) return dk + " dk kaldı";
  if (dk < 1440) return Math.round(dk / 60) + " sa kaldı";
  return Math.round(dk / 1440) + " gün kaldı";
}

// Bu uyarının bu Mac'le ilgisi: ["biz" | "ag" | "baska", etiket]
function ilgi(u, durum) {
  const yerel = new Set((durum && durum.yerel_ipler) || []);
  if (u.tur.includes("ARP")) return ["ag", "Tüm ağı ilgilendiriyor"];
  if (u.tur === "Yeni açık port") return ["biz", "Bu Mac"];
  if (yerel.has(u.kaynak)) return ["biz", "Bu Mac'ten giden"];
  if (u.hedefler.some((h) => yerel.has(h))) return ["biz", "Bu Mac'e gelen"];
  return ["baska", "Başka cihazlar arasında"];
}
let baskaAcik = false;

function seviye(risk) {
  if (risk >= 10) return ["yuksek", "Yüksek"];
  if (risk >= 3) return ["orta", "Orta"];
  return ["dusuk", "Düşük"];
}

function goster(mesaj) {
  let b = document.querySelector(".bildirim");
  if (!b) { b = document.createElement("div"); b.className = "bildirim"; document.body.append(b); }
  b.textContent = mesaj;
  b.classList.add("gorunur");
  clearTimeout(b.zaman);
  b.zaman = setTimeout(() => b.classList.remove("gorunur"), 2200);
}

// ---------- bölümler ----------

function ozetCiz(durum, uyarilar) {
  const ozet = $("ozet"), rozet = $("rozet"), ilerleme = $("ilerleme");
  let sinif, simge, baslik, alt, rozetMetin;
  ilerleme.hidden = true;

  if (!durum) {
    sinif = "kapali"; simge = SIMGE.kapali; rozetMetin = "Kapalı";
    baslik = "Servis çalışmıyor";
    alt = "Kalkan servisini kurmak için terminalde <code>./kur.sh</code> çalıştır.";
  } else if (durum.mod_ === "ogrenme") {
    sinif = "ogren"; simge = SIMGE.ogren; rozetMetin = "Öğreniyor";
    const gecen = durum.ogrenme_baslangic_us ? durum.son_paket_us - durum.ogrenme_baslangic_us : 0;
    const zamanOrani = Math.min(1, gecen / Math.max(1, durum.ogrenme_sure_us));
    const akisOrani = Math.min(1, durum.ogrenme_akis / Math.max(1, durum.min_ogrenme_akis));
    const oran = Math.min(zamanOrani, akisOrani);
    const kalanDk = Math.max(0, Math.ceil((durum.ogrenme_sure_us - gecen) / 60e6));
    baslik = "Ağını tanıyor · %" + Math.floor(oran * 100);
    alt = zamanOrani < 1
      ? `Normal trafiğin öğreniliyor, yaklaşık ${kalanDk >= 120 ? Math.round(kalanDk / 60) + " saat" : kalanDk + " dk"} kaldı. Bu sürede uyarı verilmez.`
      : `Süre doldu, en az ${durum.min_ogrenme_akis} akış bekleniyor (${durum.ogrenme_akis} toplandı).`;
    ilerleme.hidden = false;
    $("ilerleme-dolu").style.width = (oran * 100).toFixed(1) + "%";
  } else if (uyarilar.length) {
    sinif = "kotu"; simge = SIMGE.uyari; rozetMetin = "İzleniyor";
    const yuksek = uyarilar.filter((u) => u.risk >= 10).length;
    baslik = uyarilar.length === 1 ? "1 uyarı var" : `${uyarilar.length} uyarı var`;
    alt = (yuksek ? `${yuksek} tanesi yüksek riskli. ` : "") + "Son 24 saatte alışılmadık trafik görüldü.";
  } else {
    sinif = "iyi"; simge = SIMGE.kalkan; rozetMetin = "İzleniyor";
    baslik = "Her şey yolunda";
    alt = "Son 24 saatte alışılmadık bir şey görülmedi.";
  }

  ozet.className = "ozet " + sinif;
  $("ozet-simge").innerHTML = simge;
  $("ozet-baslik").textContent = baslik;
  $("ozet-alt").innerHTML = alt;
  rozet.className = "rozet " + (sinif === "kotu" ? "kotu" : sinif === "ogren" ? "ogren" : sinif === "iyi" ? "iyi" : "");
  rozet.textContent = rozetMetin;
  $("gizli-rozet").hidden = !(durum && durum.gizli && durum.gizli.acik);
}

function sayilarCiz(durum, seri) {
  const akis = seri.reduce((t, d) => t + d.akis, 0);
  const veri = seri.reduce((t, d) => t + d.bayt, 0);
  $("s-akis").textContent = durum ? sayi(akis) : "–";
  $("s-veri").textContent = durum ? bayt(veri) : "–";
  $("s-acik").textContent = durum ? sayi(durum.acik_akis) : "–";
}

function grafikCiz(seri) {
  const svg = $("grafik");
  const simdiDk = Math.floor(Date.now() / 60000);
  const harita = new Map(seri.map((d) => [Math.floor(d.dakika_us / 60e6), d]));
  const enCok = Math.max(1, ...seri.map((d) => d.akis));
  const gen = 360 / 60;
  let html = "";
  for (let i = 0; i < 60; i++) {
    const d = harita.get(simdiDk - 59 + i);
    // karekök ölçek: tek bir tarama sıçraması normal trafiği ezmesin
    const y = d ? Math.max(2, Math.sqrt(d.akis / enCok) * 52) : 1;
    html += `<rect x="${(i * gen + 0.6).toFixed(1)}" y="${(54 - y).toFixed(1)}" width="${(gen - 1.2).toFixed(1)}" height="${y.toFixed(1)}" rx="1"${d && d.anomali ? ' class="anomali"' : ""}><title>${saat((simdiDk - 59 + i) * 60e6)} · ${d ? d.akis : 0} akış${d && d.anomali ? ", " + d.anomali + " anomali" : ""}</title></rect>`;
  }
  svg.innerHTML = html;
}

function uyarilarCiz(durum, uyarilar) {
  const kutu = $("uyarilar");
  const ilgili = uyarilar.filter((u) => ilgi(u, durum)[0] !== "baska");
  $("uyari-sayi").textContent = ilgili.length || "";
  if (!durum) { kutu.innerHTML = ""; return; }
  if (!uyarilar.length) {
    ciz(kutu, `<div class="bos">${SIMGE.kalkan}<b>Uyarı yok</b>${durum.mod_ === "ogrenme" ? "Öğrenme bitince alışılmadık trafik burada görünecek." : "Alışılmadık trafik görülürse burada ve bildirim olarak çıkar."}</div>`);
    return;
  }
  const kartlar = uyarilar.map((u, i) => {
    const [sev, sevAd] = seviye(u.risk);
    const [ilgiSinif, ilgiAd] = ilgi(u, durum);
    const anahtar = `${u.kaynak}|${u.tur}`;
    const hedef = u.hedefler.join(", ") + (u.hedef_sayisi > u.hedefler.length ? ` +${u.hedef_sayisi - u.hedefler.length}` : "");
    const acik = acikAyrintilar.has(anahtar);
    const hedefIp = karsiTaraf(u, durum);
    const engelButonu = hedefIp
      ? `<button class="dugme tehlike" data-engel="${i}" ${durum.engelleme ? "" : 'disabled title="Engelleme için servisin yönetici olarak çalışması gerekiyor"'}>Engelle</button>`
      : "";
    const secim = engelSecimi === anahtar && hedefIp ? `<div class="engel-secim">
        <span><b>${kacis(hedefIp)}</b> engellensin mi?</span>
        <div>
          <button class="dugme tehlike" data-engel-sure="60" data-i="${i}">1 saat</button>
          <button class="dugme tehlike" data-engel-sure="1440" data-i="${i}">24 saat</button>
          <button class="dugme tehlike" data-engel-sure="0" data-i="${i}">Kalıcı</button>
          <button class="dugme" data-engel-vazgec>Vazgeç</button>
        </div>
      </div>` : "";
    return `<article class="uyari ${sev} ilgi-${ilgiSinif}">
      <div class="uyari-ust"><h2>${kacis(u.tur)}</h2><time title="${tarih(u.son_us)}"><span class="ilgi ${ilgiSinif}">${ilgiAd}</span> · ${once(u.son_us)}</time></div>
      <p>${kacis(u.aciklama)}</p>
      ${u.surec || u.alan_adi ? `<div class="kim">${u.surec ? `<b>${kacis(u.surec)}</b>` : ""}${u.surec && u.alan_adi ? " → " : ""}${u.alan_adi ? kacis(u.alan_adi) : ""}</div>` : ""}
      <div class="yol">${kacis(u.kaynak)} → ${kacis(hedef)}</div>
      ${acik ? `<div class="ayrinti">
        <div><span>Neden</span><span>${kacis(u.ornek_neden)}</span></div>
        ${u.surec ? `<div><span>Uygulama</span><span>${kacis(u.surec)}</span></div>` : ""}
        ${u.alan_adi ? `<div><span>Alan adı</span><span>${kacis(u.alan_adi)}</span></div>` : ""}
        ${u.arac_ipucu ? `<div><span>Muhtemel araç</span><span>${kacis(u.arac_ipucu)}</span></div>` : ""}
        <div><span>Akış</span><span>${sayi(u.akis)} akış · ${sayi(u.hedef_sayisi)} hedef · ${sayi(u.port_sayisi)} port</span></div>
        <div><span>Zaman</span><span>${tarih(u.ilk_us)} – ${saat(u.son_us)}</span></div>
        <div><span>Risk puanı</span><span>${u.risk.toLocaleString("tr-TR", { maximumFractionDigits: 1 })}</span></div>
      </div>` : ""}
      <div class="uyari-alt">
        <span class="seviye ${sev}">${sevAd}</span>
        <span class="bosluk"></span>
        <button class="dugme" data-ayrinti="${i}">${acik ? "Gizle" : "Ayrıntı"}</button>
        ${engelButonu}
        <button class="dugme ana" data-normal="${i}" title="Bu kaynaktan bu tür trafik bir daha uyarı vermesin">Bu normal</button>
      </div>
      ${secim}
    </article>`;
  });
  const benimki = kartlar.filter((_, i) => ilgi(uyarilar[i], durum)[0] !== "baska");
  const baskalari = kartlar.filter((_, i) => ilgi(uyarilar[i], durum)[0] === "baska");
  ciz(kutu, (benimki.length ? benimki.join("") : `<div class="bos">${SIMGE.kalkan}<b>Seni ilgilendiren uyarı yok</b>Aşağıdakiler ağdaki başka cihazlar arasındaki olaylar.</div>`)
    + (baskalari.length ? `<details class="baska-grup"${baskaAcik ? " open" : ""}><summary>Seninle ilgisi olmayan ${baskalari.length} olay <small>başka cihazlar arasında; bildirim gönderilmez</small></summary>${baskalari.join("")}</details>` : ""));
}

function akislarCiz(akislar) {
  const kutu = $("akislar");
  if (!akislar.length) { ciz(kutu, '<div class="bos"><b>Henüz bağlantı yok</b>Servis trafiği yakaladıkça burada görünür.</div>'); return; }
  ciz(kutu, '<p class="not">Son 50 bağlantı. Kırmızılar anomali.</p>' + akislar.map((a) => {
    const izinli = (a.neden || "").startsWith("izinli");
    const ipler = `${a.kaynak_ip}:${a.kaynak_port} → ${a.hedef_ip}:${a.hedef_port} ${a.protokol}`;
    const adli = a.surec || a.alan_adi;
    return `<div class="satir${a.anomali ? " anomali" : ""}${izinli ? " izinli" : ""}" title="${kacis(ipler + "\n" + (a.neden || "normal"))}">
      <time>${saat(a.zaman_us)}</time>
      ${adli
        ? `<span class="adres adli">${a.surec ? `<b>${kacis(a.surec)}</b>` : ""}${a.surec && a.alan_adi ? " → " : ""}${a.alan_adi ? kacis(a.alan_adi) : ""}<small>${kacis(a.hedef_ip)}:${a.hedef_port} ${kacis(a.protokol)}</small></span>`
        : `<span class="adres">${kacis(a.kaynak_ip)}<small>:${a.kaynak_port}</small> → ${kacis(a.hedef_ip)}<small>:${a.hedef_port} ${kacis(a.protokol)}</small></span>`}
      <span class="boyut">${bayt(a.bayt)}</span>
    </div>`;
  }).join(""));
}

function cihazlarHtml(cihazlar, durum) {
  const gecitIp = durum && durum.arp && durum.arp.gecit_ip;
  if (!cihazlar.length) return `<h3 class="bolum">${SIMGE.ag} Yerel ağdaki cihazlar</h3><p class="not">Henüz cihaz görülmedi. Cihazlar ağda ARP ile konuştukça burada belirir.</p>`;
  const rozet = (c) => [
    c.rol === "gecit" ? '<span class="etiket gecit">Ağ geçidi</span>' : "",
    c.rol === "bu_mac" ? '<span class="etiket bu">Bu Mac</span>' : "",
    gecitIp && c.rol !== "gecit" && c.ipler.includes(gecitIp) ? '<span class="etiket taklit" title="Bu cihaz kendini ağ geçidi gibi tanıtıyor">Ağ geçidi taklidi!</span>' : "",
    c.rastgele_mac ? '<span class="etiket" title="Telefonların gizlilik için ürettiği rastgele adres; üretici bilinemez">Gizli MAC</span>' : "",
  ].join("");
  return `<h3 class="bolum">${SIMGE.ag} Yerel ağdaki cihazlar <em>${cihazlar.length}</em></h3>` + cihazlar.map((c) => {
    const baslik = c.ad || c.uretici || (c.rastgele_mac ? "Telefon / tablet (gizli MAC)" : "Bilinmeyen cihaz");
    const alt = [c.ipler.join(", ") || "IP yok", c.mac, c.ad && c.uretici ? c.uretici : ""].filter(Boolean).join(" · ");
    return `<div class="cihaz${c.rol ? " " + c.rol : ""}">
      <div><b>${kacis(baslik)}</b>${rozet(c)}<span>${kacis(alt)}</span></div>
      <time title="İlk görülme: ${tarih(c.ilk_us)}">${once(c.son_us)}</time>
    </div>`;
  }).join("");
}

let taramaDurum = null;

function taramaHtml() {
  const t = taramaDurum;
  const calisiyor = t && t.calisiyor;
  const dugme = `<button class="dugme ana" id="tara-dugme" ${calisiyor ? "disabled" : ""}>${calisiyor ? "Taranıyor…" : "Ağımı tara"}</button>`;
  let govde = "";
  if (calisiyor) {
    govde = `<div class="ilerleme"><div style="width:${t.ilerleme}%"></div></div>
      <p class="not">${kacis(t.asama)} · %${t.ilerleme} — ${sayi(t.taranan_adres)} adres kontrol ediliyor</p>`;
  } else if (t && t.cihazlar && (t.asama === "bitti" || t.cihazlar.length)) {
    const sev = { yuksek: ["yuksek", "Yüksek"], orta: ["orta", "Orta"], dusuk: ["dusuk", "Düşük"] };
    const riskli = t.cihazlar.flatMap((c) => c.portlar).filter((p) => p.seviye === "yuksek").length;
    govde = `<p class="not">${kacis(t.ag || "")} · ${t.cihazlar.length} cihaz · ${t.cihazlar.reduce((n, c) => n + c.portlar.length, 0)} açık port${riskli ? ` · <b style="color:var(--uyari)">${riskli} yüksek riskli</b>` : ""} · ${once(t.bitis_us)}</p>`;
    govde += t.cihazlar.map((c) => {
      const ad = c.ad || c.uretici || (c.bu_mac ? "Bu Mac" : "Cihaz");
      return `<div class="tara-cihaz">
        <div class="tara-bas"><b>${kacis(c.ip)}</b> <span>${kacis(ad)}${c.bu_mac ? " · bu Mac" : ""}${c.uretici && c.ad ? " · " + kacis(c.uretici) : ""}</span></div>
        ${c.portlar.length ? c.portlar.map((p) => {
          const [s, ad2] = sev[p.seviye];
          return `<div class="tara-port ${s}"><span class="port-no">${p.port}</span><span class="port-ad">${kacis(p.servis)}${p.surum ? ` <code class="surum">${kacis(p.surum)}</code>` : ""}${p.surum_notu ? `<small class="riskli">⚠ ${kacis(p.surum_notu)}</small>` : ""}${(p.cveler || []).map((c) => `<small class="cve">🛑 ${kacis(c.cve)}${c.fidye ? " · fidye yazılımı" : ""} — ${kacis(c.baslik)} <i>(aktif sömürülüyor; sürümünü doğrula)</i></small>`).join("")}${p.oneri ? `<small>${kacis(p.oneri)}</small>` : ""}</span><span class="seviye ${s}">${ad2}</span></div>`;
        }).join("") : '<p class="tara-bos">açık port yok ✓</p>'}
      </div>`;
    }).join("");
  } else if (t && t.asama && t.asama.startsWith("hata")) {
    govde = `<p class="not">Tarama yapılamadı: ${kacis(t.asama.replace("hata: ", ""))}</p>`;
  } else {
    govde = '<p class="not">Kendi yerel ağını aktif tarayıp açık servisleri ve zayıf noktaları gösterir. Sadece bu ağı tarar, dışarı hiçbir şey gönderilmez.</p>';
  }
  return `<div class="tara-kutu"><div class="tara-ust"><h3 class="bolum">${SIMGE.ara} Ağ öz-denetimi</h3>${dugme}</div>${govde}</div>`;
}

function portlarCiz(durum, portlar, cihazlar) {
  const kutu = $("portlar");
  const acik = portlar.filter((p) => p.disari_acik);
  const yerel = portlar.filter((p) => !p.disari_acik);
  const gizli = durum && durum.gizli && durum.gizli.acik;
  const riskli = acik.filter((p) => p.seviye !== "dusuk").length;
  const ozet = `<div class="port-ozet${riskli ? " dikkat" : ""}">
      <b>${acik.length ? `${acik.length} servis ağdan erişilebilir` : "Ağa açık servis yok"}</b>
      <span>${riskli ? `${riskli} tanesine göz atmanda fayda var. ` : ""}${gizli
        ? "Gizli mod açık: yerel ağdan bu portlara gelen bağlantılar düşürülüyor."
        : acik.length ? "Kurallar sekmesinden gizli modu açarak bunları yerel ağdan gizleyebilirsin." : ""}</span>
    </div>`;
  const kart = (p) => {
    const [sev, sevAd] = { yuksek: ["yuksek", "Yüksek"], orta: ["orta", "Orta"], dusuk: ["dusuk", "Düşük"] }[p.seviye];
    return `<div class="port ${sev}">
      <div class="port-ust"><b>${kacis(p.ad)}</b><span class="seviye ${sev}">${sevAd}</span></div>
      <div class="port-alt">${p.proto} ${p.port} · ${kacis(p.surec)}${p.adres !== "*" ? " · " + kacis(p.adres) : ""}</div>
      ${p.oneri ? `<p>${kacis(p.oneri)}</p>` : ""}
    </div>`;
  };
  ciz(kutu, taramaHtml() + cihazlarHtml(cihazlar, durum) + `<h3 class="bolum">${SIMGE.kalkan} Bu Mac'in açık portları</h3>` + ozet
    + (acik.length ? `<h3 class="bolum">${SIMGE.uyari} Ağdan erişilebilir</h3>` + acik.map(kart).join("") : "")
    + (yerel.length ? `<h3 class="bolum">${SIMGE.kalkan} Sadece bu Mac'te</h3>` + yerel.map((p) =>
        `<div class="satir"><time>${p.proto}</time><span class="adres">${p.port} <small>${kacis(p.surec)}</small></span><span class="boyut">${kacis(p.adres)}</span></div>`).join("") : "")
    + '<p class="not">Dakikada bir kontrol edilir; ağa yeni bir port açılırsa uyarı gelir.</p>');
}

let gunlukSuzgec = "";
const KATEGORI = { "": "Tümü", uyari: "Uyarılar", kural: "Kurallar", ag: "Ağ", sistem: "Sistem" };

function gunlukCiz(olaylar) {
  const kutu = $("gunluk");
  const suzgec = `<div class="suzgec">${Object.entries(KATEGORI).map(([k, ad]) =>
    `<button class="${k === gunlukSuzgec ? "secili" : ""}" data-kategori="${k}">${ad}</button>`).join("")}</div>`;
  if (!olaylar.length) {
    ciz(kutu, suzgec + '<div class="bos"><b>Olay yok</b>Son 24 saatte bu kategoride kayıt yok.</div>');
    return;
  }
  // güne göre grupla
  let gun = "";
  const satirlar = olaylar.map((o) => {
    const t = new Date(o.zaman_us / 1000);
    const g = t.toLocaleDateString("tr-TR", { day: "numeric", month: "long", weekday: "long" });
    const baslik = g !== gun ? `<h3 class="bolum">${g}</h3>` : "";
    gun = g;
    return baslik + `<div class="olay ${o.seviye}" title="${kacis(o.ayrinti ? JSON.stringify(o.ayrinti, null, 1) : "")}">
      <time>${t.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time>
      <span class="kat">${KATEGORI[o.kategori] || o.kategori}</span>
      <span class="mesaj">${kacis(o.mesaj.replace(/^[⚠⛔🥷]\uFE0F?\s*/u, ""))}</span>
    </div>`;
  }).join("");
  ciz(kutu, suzgec + satirlar + '<p class="not">90 gün saklanır. Dışa aktarmak için terminalde: <code>kalkan gunluk --saat 720 --csv &gt; gunluk.csv</code></p>');
}

function kurallarCiz(durum, engeller, izinler) {
  const kutu = $("kurallar");
  kutu.engeller = engeller;
  kutu.izinler = izinler;
  const g = (durum && durum.gizli) || {};
  const gizliKapali = !durum || !durum.engelleme;
  const gizliBolumu = `<h3 class="bolum">${SIMGE.gizli} Yerel ağ</h3>
    <div class="gizli-kart${g.acik ? " acik" : ""}">
      <label class="anahtar-satir">
        <div><b>Gizli mod</b><span>${g.acik
          ? (g.arayuz ? `${kacis(g.arayuz)} üzerinde ping, port taraması ve keşif istekleri sessizce düşürülüyor.` : "Wi-Fi/Ethernet bekleniyor…")
          : "Açınca yerel ağdaki tarayıcılar bu Mac'ten hiçbir cevap alamaz. Senin bağlantıların etkilenmez."}</span></div>
        <input type="checkbox" class="anahtar" id="gizli-anahtar" ${g.acik ? "checked" : ""} ${gizliKapali ? "disabled" : ""}>
      </label>
      ${g.acik ? `<label class="secenek"><input type="checkbox" id="gizli-bonjour" ${g.bonjour ? "checked" : ""}> AirDrop, AirPlay ve yazıcı keşfine (Bonjour) izin ver</label>
      <div class="sayac">${SIMGE.gizli} <b>${sayi(g.dusurulen)}</b> istenmeyen paket düşürüldü</div>` : ""}
      ${gizliKapali && durum ? '<span class="not">Servis yönetici olarak çalışmıyor.</span>' : ""}
    </div>`;
  const arp = (durum && durum.arp) || {};
  const arpBolumu = arp.gecit_ip
    ? `<div class="arp-satir">${SIMGE.kalkan}<div><b>ARP izleme</b><span>Ağ geçidi ${kacis(arp.gecit_ip)} · ${kacis(arp.gecit_mac || "MAC bekleniyor")} · ${sayi(arp.cihaz)} cihaz görüldü. Biri kendini ağ geçidi gibi tanıtırsa uyarılırsın.</span></div></div>`
    : "";
  const engelBolumu = `<h3 class="bolum">${SIMGE.engel} Engellenenler</h3>` + (engeller.length
    ? engeller.map((e, i) => `
      <div class="izin engelli">
        <div><b>${kacis(e.ip)}</b><span>${kacis(e.neden || "elle engellendi")} · ${kalanSure(e.bitis_us)}</span></div>
        <button class="dugme" data-engel-kaldir="${i}">Kaldır</button>
      </div>`).join("")
    : `<p class="not">${durum && !durum.engelleme ? "Engelleme kapalı: servis yönetici olarak çalışmıyor." : "Engellenen adres yok. Bir uyarıda “Engelle” dersen buraya eklenir; o adresle tüm trafik kesilir."}</p>`);
  const izinBolumu = `<h3 class="bolum">${SIMGE.kalkan} İzin verilenler</h3>` + (izinler.length
    ? izinler.map((z, i) => `
      <div class="izin">
        <div><b>${kacis(z.tur)}</b><span>${kacis(z.kaynak)} · ${tarih(z.zaman_us)}</span></div>
        <button class="dugme" data-izin-kaldir="${i}">Kaldır</button>
      </div>`).join("")
    : '<p class="not">Bir uyarıda “Bu normal” dersen o kaynak buraya eklenir ve aynı tür trafik için bir daha uyarı vermez.</p>');
  ciz(kutu, gizliBolumu + arpBolumu + engelBolumu + izinBolumu);
}

function altCiz(durum) {
  const alt = $("alt");
  if (!durum) { alt.innerHTML = "<span>Kalkan</span><span></span>"; return; }
  const sol = durum.mod_ === "izleme"
    ? `Model: ${sayi(durum.egitim_akis)} akış · ${durum.son_egitim_us ? tarih(durum.son_egitim_us) : "-"}`
    : `${sayi(durum.ogrenme_akis)} / ${sayi(durum.min_ogrenme_akis)} akış toplandı`;
  alt.innerHTML = `<span>${kacis(sol)}</span><span>${kacis(durum.arayuz || "-")}</span>`;
}

// ---------- yenileme ----------

let yenileniyor = false;
async function yenile() {
  if (yenileniyor) return;
  yenileniyor = true;
  try {
    let durum = null;
    try { durum = await sor({ komut: "durum" }); } catch { durum = null; }
    let uyarilar = [], seri = [], akislar = [], izinler = [], engeller = [], portlar = [], cihazlar = [], olaylar = [];
    if (durum) {
      [uyarilar, seri] = await Promise.all([
        sor({ komut: "uyarilar", saat: 24 }).catch(() => []),
        sor({ komut: "zaman_serisi", dakika: 60 }).catch(() => []),
      ]);
      if (seciliSekme === "akislar") akislar = await sor({ komut: "akislar", adet: 50 }).catch(() => []);
      if (seciliSekme === "portlar") {
        [portlar, cihazlar, taramaDurum] = await Promise.all([
          sor({ komut: "portlar" }).catch(() => []),
          sor({ komut: "cihazlar" }).catch(() => []),
          sor({ komut: "tarama_durum" }).catch(() => taramaDurum),
        ]);
      }
      if (seciliSekme === "gunluk") olaylar = await sor({ komut: "olaylar", saat: 24, kategori: gunlukSuzgec, adet: 300 }).catch(() => []);
      if (seciliSekme === "kurallar") {
        [izinler, engeller] = await Promise.all([
          sor({ komut: "izinler" }).catch(() => []),
          sor({ komut: "engeller" }).catch(() => []),
        ]);
      }
    }
    // bu Mac'i ilgilendirenler önce (kart dizinleri bu sırayla eşleşir)
    uyarilar = [...uyarilar].sort((a, b) => (ilgi(a, durum)[0] === "baska") - (ilgi(b, durum)[0] === "baska"));
    sonUyarilar = uyarilar;
    sonDurum = durum;
    ozetCiz(durum, uyarilar.filter((u) => ilgi(u, durum)[0] !== "baska"));
    sayilarCiz(durum, seri);
    grafikCiz(seri);
    uyarilarCiz(durum, uyarilar);
    if (seciliSekme === "akislar") akislarCiz(akislar);
    if (seciliSekme === "kurallar") kurallarCiz(durum, engeller, izinler);
    if (seciliSekme === "portlar") portlarCiz(durum, portlar, cihazlar);
    if (seciliSekme === "gunluk") gunlukCiz(olaylar);
    altCiz(durum);
    if (tauri && document.visibilityState === "visible") tauri.core.invoke("goruldu").catch(() => {});
  } finally {
    yenileniyor = false;
  }
}

// ---------- etkileşim ----------

document.querySelector(".sekmeler").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-sekme]");
  if (!b) return;
  seciliSekme = b.dataset.sekme;
  document.querySelectorAll(".sekmeler button").forEach((x) => x.classList.toggle("secili", x === b));
  document.querySelectorAll(".sekme-icerik").forEach((x) => (x.hidden = x.id !== seciliSekme));
  yenile();
});

$("uyarilar").addEventListener("toggle", (e) => {
  if (e.target.classList.contains("baska-grup")) baskaAcik = e.target.open;
}, true);

$("uyarilar").addEventListener("click", async (e) => {
  const ayrinti = e.target.closest("[data-ayrinti]");
  const normal = e.target.closest("[data-normal]");
  if (ayrinti) {
    const u = sonUyarilar[ayrinti.dataset.ayrinti];
    const anahtar = `${u.kaynak}|${u.tur}`;
    acikAyrintilar.has(anahtar) ? acikAyrintilar.delete(anahtar) : acikAyrintilar.add(anahtar);
    uyarilarCiz(sonDurum, sonUyarilar);
    return;
  }
  const engel = e.target.closest("[data-engel]");
  const engelSure = e.target.closest("[data-engel-sure]");
  if (engel) {
    const u = sonUyarilar[engel.dataset.engel];
    const anahtar = `${u.kaynak}|${u.tur}`;
    engelSecimi = engelSecimi === anahtar ? null : anahtar;
    uyarilarCiz(sonDurum, sonUyarilar);
  } else if (e.target.closest("[data-engel-vazgec]")) {
    engelSecimi = null;
    uyarilarCiz(sonDurum, sonUyarilar);
  } else if (engelSure) {
    const u = sonUyarilar[engelSure.dataset.i];
    const ip = karsiTaraf(u, sonDurum);
    const sure = Number(engelSure.dataset.engelSure);
    engelSure.closest(".engel-secim").querySelectorAll("button").forEach((b) => (b.disabled = true));
    try {
      await sor({ komut: "engelle", ip, sure_dk: sure, neden: u.tur });
      engelSecimi = null;
      goster(`${ip} engellendi${sure ? " (" + (sure === 60 ? "1 saat" : "24 saat") + ")" : ""}`);
      yenile();
    } catch (err) {
      goster("Engellenemedi: " + err);
      uyarilarCiz(sonDurum, sonUyarilar);
    }
  } else if (normal) {
    const u = sonUyarilar[normal.dataset.normal];
    normal.disabled = true;
    try {
      await sor({ komut: "izin_ver", kaynak: u.kaynak, tur: u.tur });
      goster(`${u.kaynak} artık bu tür trafik için uyarı vermeyecek`);
      yenile();
    } catch (err) {
      normal.disabled = false;
      goster("Olmadı: " + err);
    }
  }
});

$("portlar").addEventListener("click", async (e) => {
  if (!e.target.closest("#tara-dugme")) return;
  try {
    const c = await sor({ komut: "tarama_baslat" });
    if (c && c.hata) { goster(c.hata); return; }
    goster("Ağ taraması başladı");
    if (taramaDurum) taramaDurum.calisiyor = true;
    yenile();
    // tarama sırasında 1 sn'de bir yenile
    const t = setInterval(async () => {
      if (seciliSekme !== "portlar") { clearInterval(t); return; }
      await yenile();
      if (taramaDurum && !taramaDurum.calisiyor) clearInterval(t);
    }, 1000);
  } catch (err) { goster("Olmadı: " + err); }
});

$("gunluk").addEventListener("click", (e) => {
  const b = e.target.closest("[data-kategori]");
  if (!b) return;
  gunlukSuzgec = b.dataset.kategori;
  yenile();
});

$("kurallar").addEventListener("change", async (e) => {
  if (e.target.id !== "gizli-anahtar" && e.target.id !== "gizli-bonjour") return;
  const anahtar = $("gizli-anahtar");
  const bonjour = $("gizli-bonjour");
  const acik = anahtar.checked;
  anahtar.disabled = true;
  try {
    await sor({ komut: "gizli_mod", acik, bonjour: bonjour ? bonjour.checked : false });
    if (e.target.id === "gizli-anahtar") goster(acik ? "Gizli mod açıldı" : "Gizli mod kapatıldı");
  } catch (err) {
    e.target.checked = !e.target.checked;
    goster("Olmadı: " + err);
  }
  anahtar.disabled = false;
  yenile();
});

$("kurallar").addEventListener("click", async (e) => {
  const kutu = $("kurallar");
  const izin = e.target.closest("[data-izin-kaldir]");
  const engel = e.target.closest("[data-engel-kaldir]");
  if (!izin && !engel) return;
  const b = izin || engel;
  b.disabled = true;
  try {
    if (izin) {
      const z = kutu.izinler[izin.dataset.izinKaldir];
      await sor({ komut: "izin_kaldir", kaynak: z.kaynak, tur: z.tur });
      goster("İzin kaldırıldı");
    } else {
      const en = kutu.engeller[engel.dataset.engelKaldir];
      await sor({ komut: "engel_kaldir", ip: en.ip });
      goster(`${en.ip} engeli kaldırıldı`);
    }
    yenile();
  } catch (err) {
    b.disabled = false;
    goster("Olmadı: " + err);
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && tauri) tauri.window.getCurrentWindow().hide();
});

if (tauri) {
  tauri.event.listen("panel_acildi", yenile);
  tauri.event.listen("yenile", yenile);
} else {
  document.body.classList.add("onizleme");
  setInterval(yenile, 5000);
}
yenile();

// Geniş görünüm penceresini aç
const panoDugme = document.getElementById("pano-ac");
if (panoDugme) {
  if (tauri) panoDugme.addEventListener("click", () => tauri.core.invoke("panoyu_ac").catch(() => {}));
  else panoDugme.addEventListener("click", () => window.open("pano.html", "_blank"));
}
