//! Bilinen zafiyet kontrolü (CISA KEV — aktif sömürülen açıklar).
//!
//! Tarama bir servisin sürümünü (banner) okuduğunda, o ürünün CISA'nın "aktif
//! sömürülüyor" listesinde olup olmadığına bakar. KEV ürün bazlıdır (sürüm aralığı
//! vermez), bu yüzden "bu üründe aktif sömürülen açık var, sürümünü doğrula" der;
//! "tam senin sürümünde" demez. Uydurma veri yok: tüm kayıtlar indirilen KEV'den.
//!
//! Liste `veri/kev.json` dosyasından okunur; `./zafiyet_guncelle.sh` ile tazelenir.

use std::path::Path;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

static KATALOG: OnceLock<Katalog> = OnceLock::new();

#[derive(Clone, Debug, Serialize)]
pub struct CveKayit {
    pub cve: String,
    pub baslik: String,
    /// fidye yazılımı kampanyalarında kullanıldığı biliniyor mu
    pub fidye: bool,
    pub tarih: String,
}

#[derive(Default)]
struct Katalog {
    surum: String,
    /// (aranan metin: vendor+product+isim, küçük harf) → kayıt
    kayitlar: Vec<(String, CveKayit)>,
}

#[derive(Deserialize)]
struct KevDosya {
    #[serde(default)]
    #[serde(rename = "catalogVersion")]
    catalog_version: String,
    vulnerabilities: Vec<KevKayit>,
}

#[derive(Deserialize)]
struct KevKayit {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject", default)]
    vendor: String,
    #[serde(default)]
    product: String,
    #[serde(rename = "vulnerabilityName", default)]
    isim: String,
    #[serde(rename = "dateAdded", default)]
    tarih: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    fidye: String,
}

/// KEV dosyasını yükler. Dosya yoksa sessizce boş kalır (özellik devre dışı).
pub fn baslat(yol: &Path) {
    let Ok(metin) = std::fs::read_to_string(yol) else { return };
    let Ok(dosya) = serde_json::from_str::<KevDosya>(&metin) else {
        crate::motor::log("Zafiyet listesi (kev.json) okunamadı; biçim beklenenden farklı.");
        return;
    };
    let kayitlar = dosya
        .vulnerabilities
        .into_iter()
        .map(|k| {
            let aranan = format!("{} {} {}", k.vendor, k.product, k.isim).to_lowercase();
            (
                aranan,
                CveKayit {
                    cve: k.cve_id,
                    baslik: if k.isim.is_empty() { k.product.clone() } else { k.isim },
                    fidye: k.fidye.eq_ignore_ascii_case("known"),
                    tarih: k.tarih,
                },
            )
        })
        .collect::<Vec<_>>();
    crate::motor::log(&format!(
        "Zafiyet listesi yüklendi (CISA KEV {}): {} aktif sömürülen açık",
        dosya.catalog_version,
        kayitlar.len()
    ));
    let _ = KATALOG.set(Katalog { surum: dosya.catalog_version, kayitlar });
}

/// Yüklü mü ve hangi sürüm.
pub fn surum() -> Option<String> {
    KATALOG.get().map(|k| k.surum.clone())
}

/// Banner'dan tanınan ürün anahtarı. Yalnızca iyi bilinen ürünler (yanlış eşleşmeyi önler).
fn urun_anahtari(banner: &str) -> Option<&'static str> {
    let b = banner.to_lowercase();
    const URUNLER: &[(&str, &str)] = &[
        ("openssh", "openssh"),
        ("apache", "apache"),
        ("httpd", "apache"),
        ("nginx", "nginx"),
        ("lighttpd", "lighttpd"),
        ("microsoft-iis", "iis"),
        ("exim", "exim"),
        ("postfix", "postfix"),
        ("dovecot", "dovecot"),
        ("proftpd", "proftpd"),
        ("vsftpd", "vsftpd"),
        ("pure-ftpd", "pure-ftpd"),
        ("samba", "samba"),
        ("mysql", "mysql"),
        ("mariadb", "mariadb"),
        ("postgresql", "postgresql"),
        ("redis", "redis"),
        ("mongodb", "mongodb"),
        ("openvpn", "openvpn"),
        ("wireguard", "wireguard"),
    ];
    URUNLER.iter().find(|(iz, _)| b.contains(iz)).map(|(_, anahtar)| *anahtar)
}

/// Banner'a göre eşleşen KEV kayıtları (en yeni önce, en çok 3).
pub fn eslesen(banner: &str) -> Vec<CveKayit> {
    let (Some(katalog), Some(anahtar)) = (KATALOG.get(), urun_anahtari(banner)) else {
        return Vec::new();
    };
    let mut hits: Vec<CveKayit> = katalog
        .kayitlar
        .iter()
        .filter(|(aranan, _)| aranan.contains(anahtar))
        .map(|(_, k)| k.clone())
        .collect();
    hits.sort_by(|a, b| b.tarih.cmp(&a.tarih));
    hits.truncate(3);
    hits
}

#[cfg(test)]
mod testler {
    use super::*;

    #[test]
    fn kev_eslesme() {
        let yol = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../veri/kev.json");
        if !yol.exists() {
            return;
        }
        baslat(&yol);
        assert!(surum().is_some());
        // OpenSSH banner'ı → KEV'de OpenSSH kaydıyla eşleşmeli
        let h = eslesen("SSH-2.0-OpenSSH_7.4");
        println!("OpenSSH eşleşen: {}", h.len());
        for c in &h {
            println!("  {} — {}", c.cve, c.baslik);
        }
        // Apache banner'ı
        let a = eslesen("Server: Apache/2.4.49");
        println!("Apache eşleşen: {}", a.len());
        // tanınmayan ürün → eşleşme yok (yanlış pozitif olmasın)
        assert!(eslesen("Server: KalkanTestServer/1.0").is_empty());
    }
}
