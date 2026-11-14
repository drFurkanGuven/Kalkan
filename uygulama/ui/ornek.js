// Tarayıcı önizlemesi için sahte servis. Tauri içinde hiç kullanılmaz.
// Durum seçmek için adrese ekle: ?durum=izleme (varsayılan) | temiz | ogrenme | kapali
(() => {
  if (window.__TAURI__) return;
  const mod = new URLSearchParams(location.search).get("durum") || "izleme";
  const simdi = Date.now() * 1000;
  const dk = 60e6;
  let izinler = [];
  let engeller = [{ ip: "45.155.205.233", baslangic_us: simdi - 30 * dk, bitis_us: simdi + 30 * dk, neden: "Port taraması şüphesi" }];

  const uyarilar = [
    {
      tur: "Alışılmadık bağlantı",
      aciklama: "Akışın genel profili normal trafiğe benzemiyor.",
      kaynak: "176.0.1.91", ilk_us: simdi - 20 * dk, son_us: simdi - 20 * dk,
      akis: 2, hedef_sayisi: 1, port_sayisi: 1, hedefler: ["224.0.0.251"], risk: 1.1,
      ornek_neden: "alışılmadık akış profili",
    },
    {
      tur: "Ortadaki adam (ARP sahteciliği) şüphesi",
      aciklama: "Ağda biri kendini ağ geçidi gibi tanıtıyor; trafiğin onun üzerinden geçiyor olabilir.",
      kaynak: "176.0.1.66", ilk_us: simdi - 3 * dk, son_us: simdi - 3 * dk,
      akis: 1, hedef_sayisi: 1, port_sayisi: 1, hedefler: ["176.0.1.1"], risk: 80,
      ornek_neden: "ARP sahteciliği: ağ geçidi 176.0.1.1 için farklı MAC duyuruldu",
      arac_ipucu: "ettercap · bettercap · arpspoof · mitmproxy", arac_aciklama: "Ağ geçidini taklit edip trafiği dinleme/değiştirme (man-in-the-middle).",
    },
    {
      tur: "Port taraması şüphesi",
      aciklama: "Tek bir kaynak kısa sürede çok sayıda farklı porta bağlanmaya çalıştı.",
      kaynak: "192.168.1.47", ilk_us: simdi - 14 * dk, son_us: simdi - 12 * dk,
      akis: 989, hedef_sayisi: 1, port_sayisi: 987, hedefler: ["192.168.1.10"], risk: 165.8,
      ornek_neden: "60 sn'de farklı port: 412 (normalde ~3)",
      arac_ipucu: "nmap · masscan · rustscan · zmap", arac_aciklama: "Bir cihazda açık servisleri arama. Zafiyet taramasının ilk adımı.",
    },
    {
      tur: "Alışılmadık veri aktarımı",
      aciklama: "Bir akışta normalin çok üstünde veri aktarıldı (büyük indirme veya veri sızdırma).",
      kaynak: "10.2.0.2", ilk_us: simdi - 95 * dk, son_us: simdi - 93 * dk,
      akis: 2, hedef_sayisi: 1, port_sayisi: 1, hedefler: ["185.86.67.240"], risk: 4.2,
      surec: "Dropbox", alan_adi: "content.dropboxapi.com",
      ornek_neden: "giden veri: 1.2 GB (normalde ~40 KB)",
    },
    {
      tur: "Alışılmadık bağlantı",
      aciklama: "Bu bağlantının genel profili öğrenilen normal trafiğe benzemiyor.",
      kaynak: "160.79.104.10", ilk_us: simdi - 300 * dk, son_us: simdi - 300 * dk,
      akis: 1, hedef_sayisi: 1, port_sayisi: 1, hedefler: ["10.2.0.2"], risk: 1.3,
      surec: "Mail", alan_adi: "imap.gmail.com",
      ornek_neden: "alışılmadık akış profili",
    },
  ];

  const seri = [];
  for (let i = 0; i < 60; i++) {
    const t = Math.floor((simdi - (59 - i) * dk) / dk) * dk;
    const akis = Math.round(12 + 10 * Math.sin(i / 6) + Math.random() * 8);
    seri.push({ dakika_us: t, akis: i === 46 ? 640 : akis, anomali: i === 46 && mod === "izleme" ? 989 : 0, bayt: akis * 48000 });
  }

  const akislar = Array.from({ length: 50 }, (_, i) => ({
    zaman_us: simdi - i * 20e6, kaynak_ip: "10.2.0.2", kaynak_port: 50000 + i,
    hedef_ip: ["142.250.187.110", "17.253.144.10", "104.16.132.229", "160.79.104.10"][i % 4],
    hedef_port: i % 5 === 0 ? 53 : 443, protokol: i % 5 === 0 ? "UDP" : "TCP",
    paket: 20 + i, bayt: 1500 * (i + 3) * (i % 7 + 1), sure_ms: 1200, risk: 0.2,
    anomali: mod === "izleme" && i === 7, neden: i === 7 ? "60 sn'de farklı port: 412 (normalde ~3)" : "",
    surec: i % 5 === 0 ? "mDNSResponder" : ["Google Chrome", "Safari", "Spotify", "Mail"][i % 4],
    alan_adi: i % 5 === 0 ? null : ["www.google.com", "www.apple.com", "api.spotify.com", "imap.gmail.com"][i % 4],
  }));

  const durum = {
    mod_: mod === "ogrenme" ? "ogrenme" : "izleme", arayuz: "utun6",
    ogrenme_baslangic_us: simdi - 9 * 3600e6, ogrenme_sure_us: 24 * 3600e6,
    ogrenme_akis: 2140, min_ogrenme_akis: 300, son_egitim_us: simdi - 26 * 3600e6,
    egitim_akis: 18342, toplam_akis: 52011, anomali: 992, acik_akis: 23,
    son_paket_us: simdi, baslangic_us: simdi - 30 * 3600e6,
    arp: { gecit_ip: "176.0.1.1", gecit_mac: "a4:2b:b0:1c:7e:02", arayuz: "en0", cihaz: 7 },
    gizli: { acik: false, bonjour: false, arayuz: null, dusurulen: 0 },
    engelleme: true, yerel_ipler: ["10.2.0.2", "176.0.1.26"],
  };

  window.sahteSor = async (istek) => {
    await new Promise((r) => setTimeout(r, 60));
    if (mod === "kapali") throw "servis_kapali";
    const aktif = mod === "izleme"
      ? uyarilar.filter((u) => !izinler.some((z) => z.kaynak === u.kaynak && z.tur === u.tur))
      : [];
    switch (istek.komut) {
      case "durum": return durum;
      case "uyarilar": return aktif;
      case "zaman_serisi": return seri;
      case "akislar": return akislar.slice(0, istek.adet || 50);
      case "izinler": return izinler;
      case "izin_ver": izinler.unshift({ kaynak: istek.kaynak, tur: istek.tur, zaman_us: Date.now() * 1000 }); return { tamam: true };
      case "izin_kaldir": izinler = izinler.filter((z) => !(z.kaynak === istek.kaynak && z.tur === istek.tur)); return { tamam: true };
      case "engeller": return engeller;
      case "olaylar": {
        const o = [
          { zaman_us: simdi - 2 * dk, kategori: "uyari", seviye: "kritik", mesaj: "⚠ Ortadaki adam (ARP sahteciliği) şüphesi: ağ geçidi 176.0.1.1 için farklı MAC duyuruldu" },
          { zaman_us: simdi - 9 * dk, kategori: "ag", seviye: "uyari", mesaj: "Ağa yeni cihaz katıldı: Raspberry Pi Foundation · 176.0.1.40 · b8:27:eb:aa:bb:cc" },
          { zaman_us: simdi - 25 * dk, kategori: "kural", seviye: "uyari", mesaj: "⛔ Engellendi: 45.155.205.233 (60 dk) · Port taraması şüphesi", ayrinti: { islem: "engelle", ip: "45.155.205.233", sure_dk: 60 } },
          { zaman_us: simdi - 40 * dk, kategori: "kural", seviye: "bilgi", mesaj: "🥷 Gizli mod açık: en0 üzerinde istenmeyen gelen trafik düşürülüyor (Bonjour izinli)" },
          { zaman_us: simdi - 61 * dk, kategori: "ag", seviye: "bilgi", mesaj: "Ağ değişti: utun6 + en0 (yerel ağ) → en0" },
          { zaman_us: simdi - 62 * dk, kategori: "sistem", seviye: "bilgi", mesaj: "Model eğitildi: 18342 akış · orman eşiği 0.156 · sapma eşiği 6.0" },
          { zaman_us: simdi - 26 * 3600e6, kategori: "sistem", seviye: "bilgi", mesaj: "Kalkan servisi başladı · veri: /Library/Application Support/Kalkan" },
        ];
        return istek.kategori ? o.filter((x) => x.kategori === istek.kategori) : o;
      }
      case "tarama_baslat": durum._tarama = { calisiyor: true, asama: "cihaz keşfi", ilerleme: 0, taranan_adres: 254, ag: "176.0.1.0/24", cihazlar: [], bitis_us: 0 }; return { baslatildi: true };
      case "tarama_durum": {
        const t = durum._tarama;
        if (!t) return { calisiyor: false, asama: "", cihazlar: [] };
        if (t.calisiyor) { t.ilerleme += 25; if (t.ilerleme >= 100) { t.calisiyor = false; t.asama = "bitti"; t.ilerleme = 100; t.bitis_us = Date.now() * 1000;
          t.cihazlar = [
            { ip: "176.0.1.1", mac: "00:21:9b:a5:4b:18", ad: null, uretici: "Dell", bu_mac: false, portlar: [
              { port: 22, servis: "Uzaktan Giriş (SSH)", seviye: "yuksek", oneri: "Kullanmıyorsan kapat", surum: "SSH-2.0-OpenSSH_7.4", surum_notu: "Eski OpenSSH (7.4); güncellemeyi düşün.", cveler: [{ cve: "CVE-2024-6387", baslik: "OpenSSH RCE (regreSSHion)", fidye: false, tarih: "2024-07-01" }] },
              { port: 80, servis: "Web arayüzü (HTTP)", seviye: "orta", oneri: "Yönlendirici paneli olabilir; güçlü parola kullan", surum: "Apache/2.4.49", cveler: [{ cve: "CVE-2021-41773", baslik: "Apache HTTP Server Path Traversal", fidye: true, tarih: "2021-11-03" }] },
              { port: 53, servis: "DNS", seviye: "dusuk", oneri: "" } ] },
            { ip: "176.0.1.26", mac: null, ad: "furkan-macbook-air", uretici: "Apple", bu_mac: true, portlar: [
              { port: 7000, servis: "AirPlay alıcısı", seviye: "orta", oneri: "Kullanmıyorsan kapat: AirPlay Alıcısı" } ] },
            { ip: "176.0.1.40", mac: "b8:27:eb:aa:bb:cc", ad: null, uretici: "Raspberry Pi Foundation", bu_mac: false, portlar: [] },
          ]; } else { t.asama = t.ilerleme < 40 ? "cihaz keşfi" : "port taraması"; } }
        return t;
      }
      case "cihazlar": return [
        { mac: "00:21:9b:a5:4b:18", ipler: ["176.0.1.1"], ad: null, uretici: "Dell", rastgele_mac: false, rol: "gecit", ilk_us: simdi - 9 * 3600e6, son_us: simdi - 20e6 },
        { mac: "8c:85:90:12:34:56", ipler: ["176.0.1.26"], ad: "furkan-macbook-air", uretici: "Apple", rastgele_mac: false, rol: "bu_mac", ilk_us: simdi - 9 * 3600e6, son_us: simdi },
        { mac: "5e:1f:a2:33:44:55", ipler: ["176.0.1.91"], ad: "furkan-iphone", uretici: null, rastgele_mac: true, rol: "", ilk_us: simdi - 3 * 3600e6, son_us: simdi - 90e6 },
        { mac: "b8:27:eb:aa:bb:cc", ipler: ["176.0.1.40"], ad: null, uretici: "Raspberry Pi Foundation", rastgele_mac: false, rol: "", ilk_us: simdi - 2 * 3600e6, son_us: simdi - 600e6 },
        { mac: "fa:11:22:33:44:55", ipler: ["176.0.1.158"], ad: null, uretici: null, rastgele_mac: true, rol: "", ilk_us: simdi - 40 * 60e6, son_us: simdi - 300e6 },
      ];
      case "portlar": return [
        { proto: "TCP", port: 22, adres: "*", surec: "launchd", pid: 1, kullanici: "root", disari_acik: true, ad: "Uzaktan Giriş (SSH)", seviye: "yuksek", oneri: "Kullanmıyorsan kapat: Sistem Ayarları → Genel → Paylaşma → Uzaktan Giriş" },
        { proto: "TCP", port: 7000, adres: "*", surec: "ControlCenter", pid: 660, kullanici: "furkanguven", disari_acik: true, ad: "AirPlay alıcısı", seviye: "orta", oneri: "Kullanmıyorsan kapat: Sistem Ayarları → Genel → AirDrop ve Handoff → AirPlay Alıcısı" },
        { proto: "TCP", port: 57565, adres: "*", surec: "rapportd", pid: 663, kullanici: "furkanguven", disari_acik: true, ad: "Handoff / Continuity (sistem)", seviye: "dusuk", oneri: "" },
        { proto: "TCP", port: 5432, adres: "127.0.0.1", surec: "postgres", pid: 900, kullanici: "furkanguven", disari_acik: false, ad: "PostgreSQL veritabanı", seviye: "dusuk", oneri: "" },
      ];
      case "gizli_mod":
        durum.gizli = { acik: istek.acik, bonjour: istek.bonjour, arayuz: istek.acik ? "en0" : null, dusurulen: istek.acik ? 37 : 0 };
        return { tamam: true, gizli: durum.gizli };
      case "engelle":
        if (["10.2.0.2", "176.0.1.26"].includes(istek.ip)) throw `${istek.ip} engellenemez: bu Mac'in kendi adresi`;
        engeller.unshift({ ip: istek.ip, baslangic_us: Date.now() * 1000, bitis_us: istek.sure_dk ? (Date.now() + istek.sure_dk * 60000) * 1000 : 0, neden: istek.neden });
        return { tamam: true };
      case "engel_kaldir": engeller = engeller.filter((e) => e.ip !== istek.ip); return { tamam: true };
      default: throw "bilinmeyen komut";
    }
  };
})();
