<div align="center">

# 🛡️ Kalkan

**Mac'in için sessiz çalışan, öğrenen ağ güvenlik kalkanı.**

Ağını izler, neyin normal olduğunu öğrenir, alışılmadık ve şüpheli trafiği yakalar — bildiğin dille anlatır.

![Platform](https://img.shields.io/badge/platform-macOS%2011%2B-black)
![Rust](https://img.shields.io/badge/Rust-2024-orange)
![Lisans](https://img.shields.io/badge/lisans-source--available-blue)

</div>

---

## Kalkan nedir?

Kalkan, kişisel Mac kullanıcıları ve küçük ofisler için yazılmış bir **ağ izleme ve güvenlik** uygulamasıdır. Arka planda sessizce çalışır, Mac'inin ağ trafiğini izler ve:

- İlk 24 saat **normal trafiğini öğrenir** (hiçbir şey etiketlemene gerek yok).
- Sonra alışılmadık bağlantıları, port taramalarını, ortadaki adam saldırılarını **kendi kendine yakalar**.
- Her uyarıyı IP yerine **"Chrome → google.com"** gibi anlaşılır biçimde gösterir.
- İstersen şüpheli bir adresi **engeller**, seni yerel ağda **görünmez** yapar.

Tamamen **Rust** ile yazılmıştır: hafif (işlemcinin binde biri, ~22 MB bellek), hızlı ve bağımsız.

> **Gizlilik önce gelir.** Kalkan hiçbir trafiğini, hiçbir veriyi dışarı göndermez. Her şey senin Mac'inde kalır.

---

## Özellikler

| | |
|---|---|
| 🧠 **Öğrenen tespit** | Isolation Forest + istatistiksel sapma; ağını öğrenip anomali yakalar |
| 🔎 **Anlaşılır uyarılar** | Bağlantıyı açan uygulama (libproc) ve alan adı (DNS/SNI); IP değil isim |
| 🥷 **Gizli mod** | Yerel ağdan gelen tarama/keşif isteklerini sessizce düşürür |
| ⛔ **Engelleme** | Şüpheli IP'yi tek tıkla engelle (1 sa / 24 sa / kalıcı), pf tabanlı |
| 📡 **ARP izleme** | Ortadaki adam (ARP sahteciliği) ve yerel ağ taraması tespiti |
| 🔌 **Port denetimi** | Mac'inde dışarı açık servisleri listeler, ağa yeni port açılınca uyarır |
| 🔬 **Ağ öz-denetimi** | Kendi ağını aktif tarar: cihazlar, açık portlar, servis sürümleri |
| 🛑 **Zafiyet kontrolü** | Okunan sürümü CISA KEV (aktif sömürülen açıklar) listesiyle karşılaştırır |
| 📓 **Olay günlüğü** | Her şey kayıt altında; kategori süzgeci + CSV dışa aktarma |
| 🖥️ **Mac arayüzü** | Menü çubuğu paneli + ayrı geniş görünüm penceresi; açık/koyu tema |

---

## Kurulum (normal kullanıcı)

> Terminal gerekmez. Üç adım.

1. **İndir:** [Sürümler (Releases) sayfasından](../../releases/latest) `Kalkan-Kurulum.pkg` dosyasını indir.
2. **Çift tıkla.** Paket imzasız olduğu için macOS ilk seferde uyarabilir:
   → Dosyaya **sağ tıkla → Aç → Aç**. (Bir kez; sonra normal açılır.)
3. **Yükleyici** açılır → *İleri → Kur* → **Mac şifreni gir**. Bitti.

Kurulduktan sonra menü çubuğunda 🛡️ kalkan simgesi belirir. Mac her açıldığında kendiliğinden başlar.

**İlk 24 saat** Kalkan ağını öğrenir ve bu sürede anomali uyarısı vermez — ama ARP izleme, port denetimi, engelleme, gizli mod ve ağ taraması ilk andan çalışır.



---

## Kullanım

**Menü çubuğu simgesi:**
- **Sol tık** → açılır panel (durum, grafik, uyarılar, bağlantılar, ağ, kurallar, günlük).
- Panelin sağ üstündeki **genişlet düğmesi** → tam ekran geniş görünüm penceresi.
- **Sağ tık** → menü (durum, geniş görünüm, açılışta başlat, çıkış).

**Panelde yapabileceklerin:**
- Bir uyarıda **"Bu normal"** → o kaynak bir daha uyarı vermez.
- Bir uyarıda **"Engelle"** → o adresi seçtiğin süre boyunca keser.
- **Kurallar → Yerel ağ → Gizli mod** → kalabalık/halka açık ağlarda seni gizler.
- **Ağ → "Ağımı tara"** → kendi ağında açık servisleri, sürümlerini ve bilinen açıkları gör.

**Terminal komutları (isteğe bağlı):**
```bash
kalkan durum       # servis durumu ve son uyarılar
kalkan tara        # kendi ağını aktif tara
kalkan gunluk      # olay günlüğü (--saat 720 --csv > gunluk.csv ile dışa aktar)
kalkan uyarilar    # kayıtlı anomalileri grupla
```

---

## Gizlilik

- Hiçbir ağ verisi, alan adı ya da uyarı **dışarı gönderilmez**. Tüm işlem yereldir.
- Veritabanı (tarama geçmişi dahil) sadece `root` tarafından okunabilir (`0600`).
- Dışarıya tek erişim, senin başlattığın güncelleme betikleridir: cihaz üreticisi (IEEE OUI) ve zafiyet (CISA KEV) **listelerini indirir** — senin hiçbir bilgini göndermez.

---

## Kaynak koddan derleme (geliştirici)

**Gereksinimler:** macOS 11+, [Rust](https://rustup.rs) (2024 sürümü), Node.js 18+, Xcode Command Line Tools.

```bash
git clone <depo-adresin> kalkan && cd kalkan

# Cihaz üreticisi ve zafiyet listelerini indir (ilk sefer)
./oui_guncelle.sh
./zafiyet_guncelle.sh

# Çift tıklanan kurulum paketini üret
./paket_yap.sh          # → Kalkan-Kurulum.pkg

# veya doğrudan kur (terminalden, launchd servisi olarak)
./kur.sh                # 24 saat öğrenme; hızlı deneme için ./kur.sh 2h
```

**Proje yapısı:**
```
crates/cekirdek   Motor: paket çözme, akışlar, Isolation Forest, DNS/SNI, uyarı türleri
crates/servis     Arka plan servisi: canlı yakalama, engelleme, ARP, port, tarama, günlük
crates/kalkan     Komut satırı aracı (kalkan ...)
uygulama/         Tauri menü çubuğu uygulaması (Rust + HTML/JS arayüz)
veri/             İndirilen listeler (oui.csv, kev.json)
```

**Listeleri güncel tut:** CISA KEV ve IEEE OUI listeleri zamanla değişir. Ara sıra `./zafiyet_guncelle.sh` ve `./oui_guncelle.sh` çalıştırıp `./kur.sh` ile servise geçir.

---

## Kaldırma

```bash
./kaldir.sh            # servisi ve uygulamayı kaldır (öğrenilen model kalır)
./kaldir.sh --hepsi    # her şeyi sil (model, veritabanı, loglar dahil)
```

---

## Yol haritası

- ✅ **Faz 1–4:** Motor, servis, Mac uygulaması, anlaşılır uyarılar
- ✅ **Ek:** Engelleme, gizli mod, ARP izleme, port denetimi, ağ öz-denetimi, sürüm + CISA KEV zafiyet kontrolü, olay günlüğü, geniş görünüm, .pkg kurulum
- ⏳ **Faz 5:** Yeni tespitler (beaconing / "eve arama", DNS tüneli), pcap test seti
- ⏳ **Faz 6:** Küçük ofis — ağ geneli izleme, çoklu cihaz, haftalık rapor, **imzalı + noterli dağıtım**

---

## Lisans

Kaynak görüntülenebilir (source-available) — bkz. [LICENSE](LICENSE). Kişisel kullanım serbest; yeniden dağıtım izne tabidir. İstersen MIT/Apache-2.0 ile tamamen açık kaynağa çevirebilirsin.

<div align="center">
<sub>Rust ❤️ ile yapıldı · Gizliliğine saygılı ağ güvenliği</sub>
</div>
