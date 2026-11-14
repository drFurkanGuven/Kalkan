//! ARP izleme: ortadaki adam (ARP sahteciliği) ve yerel ağ taraması tespiti.
//!
//! Sahte ARP saldırısında saldırgan ağa "ağ geçidinin (yönlendiricinin) MAC adresi
//! benim" diye cevap yayar; kurbanların internet trafiği onun üzerinden akar.
//! İki işarete bakıyoruz:
//!   1. Ağ geçidinin IP'si için bildiğimizden farklı bir MAC duyuruluyor.
//!   2. Ağ geçidi olduğunu iddia eden MAC, aynı zamanda başka bir cihazın IP'sini de
//!      kullanıyor (arpspoof / ettercap / bettercap'in tipik izi).
//!
//! ARP taraması: bir cihaz kısa sürede çok sayıda farklı adresi "kimde?" diye sorar.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use cekirdek::paket::{ARP_ISTEK, ArpPaket, mac_yazi};
use serde::Serialize;

const PENCERE_US: u64 = 60 * 1_000_000;
/// 60 sn'de bu kadar farklı adresi soran cihaz "tarama yapıyor" sayılır
const TARAMA_ESIGI: usize = 20;
/// Aynı uyarı en fazla bu sıklıkla
const UYARI_ARASI_US: u64 = 10 * 60 * 1_000_000;
/// Ağ geçidinin yeni MAC'i bu kadar süre tek başına görülürse (eskisi hiç görünmezse) kabul edilir
const KABUL_SURESI_US: u64 = 10 * 60 * 1_000_000;

/// Kaydedilecek bir ARP olayı (motor bunu uyarı olarak yazar).
pub struct Olay {
    pub zaman_us: u64,
    pub kaynak: Ipv4Addr,
    pub hedef: Ipv4Addr,
    pub paket: u64,
    pub risk: f64,
    pub neden: String,
}

/// Panel için özet.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ArpDurumu {
    pub gecit_ip: Option<String>,
    pub gecit_mac: Option<String>,
    pub arayuz: Option<String>,
    pub cihaz: usize,
}

/// Yerel ağda görülen bir cihaz (panelde liste için).
#[derive(Clone, Debug, Serialize)]
pub struct Cihaz {
    pub mac: String,
    pub ipler: Vec<String>,
    /// mDNS (Bonjour) duyurusundaki ad, ör. "furkan-iphone"
    pub ad: Option<String>,
    /// IEEE OUI listesinden üretici (liste kuruluysa)
    pub uretici: Option<String>,
    /// Gizlilik için rastgele üretilmiş MAC (iPhone/Android "özel adres")
    pub rastgele_mac: bool,
    /// "gecit" | "bu_mac" | ""
    pub rol: &'static str,
    pub ilk_us: u64,
    pub son_us: u64,
}

/// IEEE OUI listesi (oui.csv): MAC'in ilk 3 baytı → üretici.
pub fn oui_yukle(yol: &Path) -> HashMap<[u8; 3], String> {
    let Ok(metin) = std::fs::read_to_string(yol) else { return HashMap::new() };
    metin
        .lines()
        .skip(1)
        .filter_map(|satir| {
            // MA-L,0021E9,"Apple, Inc.",adres...
            let mut p = satir.splitn(3, ',');
            p.next()?;
            let onek = p.next()?;
            let kalan = p.next()?;
            let ad = match kalan.strip_prefix('"') {
                Some(t) => t.split('"').next()?,
                None => kalan.split(',').next()?,
            };
            let b = u32::from_str_radix(onek, 16).ok()?;
            let kisa = ad
                .split(',')
                .next()?
                .trim()
                .trim_end_matches(" Inc.")
                .trim_end_matches(" Inc")
                .trim_end_matches(" Corporation")
                .trim_end_matches(" Co.")
                .trim()
                .to_string();
            Some(([(b >> 16) as u8, (b >> 8) as u8, b as u8], kisa))
        })
        .collect()
}

#[derive(Default)]
pub struct ArpIzleyici {
    /// MAC → (ilk, son görülme)
    gorulme: HashMap<[u8; 6], (u64, u64)>,
    /// bu oturumda ilk kez görülen MAC'ler (motor alıp ağ başına kaydeder)
    yeni_macler: Vec<[u8; 6]>,
    /// mDNS'ten öğrenilen cihaz adları
    adlar: HashMap<Ipv4Addr, String>,
    oui: Arc<HashMap<[u8; 3], String>>,
    /// Test için sabit ağ geçidi (verilmezse sistemden okunur)
    sabit_gecit: Option<Ipv4Addr>,
    gecit: Option<(Ipv4Addr, String)>,
    gecit_mac: Option<[u8; 6]>,
    /// Ağ geçidi için duyurulan farklı MAC: (mac, ilk görülme, son görülme)
    aday_mac: Option<([u8; 6], u64, u64)>,
    eski_mac_son_gorulme: u64,
    ip_mac: HashMap<Ipv4Addr, [u8; 6]>,
    mac_ipler: HashMap<[u8; 6], HashSet<Ipv4Addr>>,
    /// MAC → (pencere başlangıcı, sorduğu farklı adresler, uyarı verildi mi)
    istekler: HashMap<[u8; 6], (u64, HashSet<Ipv4Addr>, bool)>,
    son_uyari: HashMap<(String, &'static str), u64>,
    kendi_mac: HashSet<[u8; 6]>,
}

/// Fiziksel karttaki varsayılan ağ geçidi (VPN açıkken de yerel yönlendiriciyi verir).
fn sistem_gecidi() -> Option<(Ipv4Addr, String)> {
    let c = Command::new("/usr/sbin/netstat").args(["-rn", "-f", "inet"]).output().ok()?;
    String::from_utf8_lossy(&c.stdout).lines().find_map(|s| {
        let p: Vec<&str> = s.split_whitespace().collect();
        if p.len() >= 4 && p[0] == "default" && p[3].starts_with("en") {
            Some((p[1].parse().ok()?, p[3].to_string()))
        } else {
            None
        }
    })
}

/// Sistemin ARP tablosundaki MAC (ilk değer için).
fn sistem_mac(ip: Ipv4Addr) -> Option<[u8; 6]> {
    let c = Command::new("/usr/sbin/arp").args(["-n", &ip.to_string()]).output().ok()?;
    let metin = String::from_utf8_lossy(&c.stdout);
    let mac = metin.split(" at ").nth(1)?.split_whitespace().next()?;
    mac_coz(mac)
}

fn mac_coz(s: &str) -> Option<[u8; 6]> {
    let p: Vec<u8> = s.split(':').filter_map(|x| u8::from_str_radix(x, 16).ok()).collect();
    p.try_into().ok()
}

fn kendi_macleri() -> HashSet<[u8; 6]> {
    let Ok(c) = Command::new("/sbin/ifconfig").output() else { return HashSet::new() };
    String::from_utf8_lossy(&c.stdout)
        .lines()
        .filter_map(|s| s.trim().strip_prefix("ether ").and_then(mac_coz))
        .collect()
}

impl ArpIzleyici {
    pub fn new(sabit_gecit: Option<Ipv4Addr>, oui_yolu: &Path) -> Self {
        let oui = oui_yukle(oui_yolu);
        if !oui.is_empty() {
            crate::motor::log(&format!("Üretici listesi yüklendi: {} kayıt", oui.len()));
        }
        let mut a = ArpIzleyici {
            sabit_gecit,
            kendi_mac: kendi_macleri(),
            oui: Arc::new(oui),
            ..Default::default()
        };
        a.gecidi_yenile();
        a
    }

    /// Ağ geçidini (yeniden) öğren. Ağ değiştiyse bilinen MAC sıfırlanır.
    pub fn gecidi_yenile(&mut self) {
        let yeni = match self.sabit_gecit {
            Some(ip) => Some((ip, "test".to_string())),
            None => sistem_gecidi(),
        };
        if yeni != self.gecit {
            self.gecit = yeni;
            self.gecit_mac = match (&self.gecit, self.sabit_gecit) {
                (Some((ip, _)), None) => sistem_mac(*ip),
                _ => None, // ilk duyurudan öğrenilir
            };
            self.aday_mac = None;
            self.ip_mac.clear();
            self.mac_ipler.clear();
            self.istekler.clear();
            self.gorulme.clear();
            self.adlar.clear();
            self.yeni_macler.clear();
            if let Some((ip, ad)) = &self.gecit {
                let mac = self.gecit_mac.as_ref().map(mac_yazi);
                crate::gunluk::bilgi(
                    crate::gunluk::Kategori::Ag,
                    &format!("ARP izleme: ağ geçidi {ip} ({}) · {ad}", mac.as_deref().unwrap_or("MAC bekleniyor")),
                    serde_json::json!({"gecit_ip": ip.to_string(), "gecit_mac": mac, "arayuz": ad}),
                );
            }
        }
    }

    pub fn durum(&self) -> ArpDurumu {
        ArpDurumu {
            gecit_ip: self.gecit.as_ref().map(|(ip, _)| ip.to_string()),
            gecit_mac: self.gecit_mac.as_ref().map(mac_yazi),
            arayuz: self.gecit.as_ref().map(|(_, a)| a.clone()),
            cihaz: self.ip_mac.len(),
        }
    }

    fn kisitla(&mut self, anahtar: String, tur: &'static str, zaman_us: u64) -> bool {
        match self.son_uyari.get(&(anahtar.clone(), tur)) {
            Some(&t) if zaman_us.saturating_sub(t) < UYARI_ARASI_US => false,
            _ => {
                self.son_uyari.insert((anahtar, tur), zaman_us);
                true
            }
        }
    }

    /// Ağın kimliği: ağ geçidinin MAC adresi (ev ve okul ağı karışmasın diye).
    pub fn ag_kimligi(&self) -> Option<String> {
        self.gecit_mac.as_ref().map(mac_yazi)
    }

    /// İlk kez görülen MAC'leri ver (ağ kimliği belli olduktan sonra).
    pub fn yeni_cihazlari_al(&mut self) -> Vec<[u8; 6]> {
        if self.gecit_mac.is_none() {
            return Vec::new();
        }
        std::mem::take(&mut self.yeni_macler)
    }

    /// mDNS'ten öğrenilen cihaz adı.
    pub fn ad_ekle(&mut self, ip: Ipv4Addr, ad: String) {
        self.adlar.insert(ip, ad);
    }

    /// Ağda görülen cihazlar: önce ağ geçidi ve bu Mac, sonra IP sırasıyla.
    pub fn cihazlar(&self) -> Vec<Cihaz> {
        let gecit = self.gecit.as_ref().map(|(ip, _)| *ip);
        let mut liste: Vec<Cihaz> = self
            .gorulme
            .iter()
            .map(|(mac, (ilk, son))| {
                let ipler: BTreeSet<Ipv4Addr> = self.mac_ipler.get(mac).cloned().unwrap_or_default().into_iter().collect();
                let rol = if self.kendi_mac.contains(mac) {
                    "bu_mac"
                } else if gecit.is_some_and(|g| ipler.contains(&g)) && Some(*mac) == self.gecit_mac {
                    "gecit"
                } else {
                    ""
                };
                Cihaz {
                    mac: mac_yazi(mac),
                    ad: ipler.iter().find_map(|ip| self.adlar.get(ip).cloned()),
                    ipler: ipler.iter().map(|ip| ip.to_string()).collect(),
                    uretici: self.oui.get(&[mac[0], mac[1], mac[2]]).cloned(),
                    rastgele_mac: mac[0] & 0x02 != 0,
                    rol,
                    ilk_us: *ilk,
                    son_us: *son,
                }
            })
            .collect();
        let sira = |c: &Cihaz| match c.rol {
            "gecit" => 0,
            "bu_mac" => 1,
            _ => 2,
        };
        liste.sort_by_key(|c| {
            let ip: Option<Ipv4Addr> = c.ipler.first().and_then(|s| s.parse().ok());
            (sira(c), ip.map(u32::from).unwrap_or(u32::MAX))
        });
        liste
    }

    pub fn paket(&mut self, a: &ArpPaket, zaman_us: u64) -> Vec<Olay> {
        let mut olaylar = Vec::new();
        if !self.gorulme.contains_key(&a.gonderen_mac) {
            self.yeni_macler.push(a.gonderen_mac);
        }
        let g = self.gorulme.entry(a.gonderen_mac).or_insert((zaman_us, zaman_us));
        g.1 = zaman_us;
        let unspecified = a.gonderen_ip.is_unspecified();
        if !unspecified {
            self.ip_mac.insert(a.gonderen_ip, a.gonderen_mac);
            self.mac_ipler.entry(a.gonderen_mac).or_default().insert(a.gonderen_ip);
        }

        // 1) Ağ geçidi adına konuşan biri
        if let Some((gecit_ip, _)) = self.gecit
            && a.gonderen_ip == gecit_ip
        {
            match self.gecit_mac {
                None => self.gecit_mac = Some(a.gonderen_mac),
                Some(bilinen) if bilinen == a.gonderen_mac => {
                    self.eski_mac_son_gorulme = zaman_us;
                }
                Some(bilinen) => {
                    let ilk = match self.aday_mac {
                        Some((m, ilk, _)) if m == a.gonderen_mac => ilk,
                        _ => zaman_us,
                    };
                    self.aday_mac = Some((a.gonderen_mac, ilk, zaman_us));
                    // Yönlendirici gerçekten değiştiyse: yeni MAC uzun süredir tek başına
                    if zaman_us.saturating_sub(ilk) >= KABUL_SURESI_US
                        && zaman_us.saturating_sub(self.eski_mac_son_gorulme) >= KABUL_SURESI_US
                    {
                        crate::gunluk::uyari(
                            crate::gunluk::Kategori::Ag,
                            &format!("ARP izleme: ağ geçidinin yeni MAC adresi kabul edildi ({})", mac_yazi(&a.gonderen_mac)),
                            serde_json::json!({"gecit_ip": gecit_ip.to_string(), "eski_mac": mac_yazi(&bilinen), "yeni_mac": mac_yazi(&a.gonderen_mac)}),
                        );
                        self.gecit_mac = Some(a.gonderen_mac);
                        self.aday_mac = None;
                    } else if self.kisitla(mac_yazi(&a.gonderen_mac), "sahte", zaman_us) {
                        // Bu MAC başka bir cihazın IP'sini de kullanıyor mu?
                        let diger: Vec<Ipv4Addr> = self
                            .mac_ipler
                            .get(&a.gonderen_mac)
                            .map(|s| s.iter().filter(|ip| **ip != gecit_ip).copied().collect())
                            .unwrap_or_default();
                        let saldirgan = diger.first().copied();
                        let ek = match saldirgan {
                            Some(ip) => format!("; bu MAC aynı zamanda {ip} cihazına ait"),
                            None => String::new(),
                        };
                        olaylar.push(Olay {
                            zaman_us,
                            kaynak: saldirgan.unwrap_or(gecit_ip),
                            hedef: gecit_ip,
                            paket: 1,
                            risk: if saldirgan.is_some() { 80.0 } else { 40.0 },
                            neden: format!(
                                "ARP sahteciliği: ağ geçidi {gecit_ip} için farklı MAC duyuruldu ({} → {}){ek}",
                                mac_yazi(&bilinen),
                                mac_yazi(&a.gonderen_mac)
                            ),
                        });
                    }
                }
            }
        }

        // 2) ARP taraması: çok sayıda farklı adres soran cihaz
        let gratuitous = a.gonderen_ip == a.hedef_ip;
        if a.islem == ARP_ISTEK && !gratuitous && !self.kendi_mac.contains(&a.gonderen_mac) {
            let kayit = self.istekler.entry(a.gonderen_mac).or_insert((zaman_us, HashSet::new(), false));
            if zaman_us.saturating_sub(kayit.0) > PENCERE_US {
                *kayit = (zaman_us, HashSet::new(), false);
            }
            kayit.1.insert(a.hedef_ip);
            if kayit.1.len() >= TARAMA_ESIGI && !kayit.2 {
                kayit.2 = true;
                let sayi = kayit.1.len();
                let kaynak = if unspecified { Ipv4Addr::UNSPECIFIED } else { a.gonderen_ip };
                if self.kisitla(mac_yazi(&a.gonderen_mac), "tarama", zaman_us) {
                    olaylar.push(Olay {
                        zaman_us,
                        kaynak,
                        hedef: a.hedef_ip,
                        paket: sayi as u64,
                        risk: 10.0 + sayi as f64 / 5.0,
                        neden: format!(
                            "ARP taraması: {} ({}) 60 sn'de {sayi}+ farklı adresi yokladı",
                            kaynak,
                            mac_yazi(&a.gonderen_mac)
                        ),
                    });
                }
            }
        }
        olaylar
    }
}

#[cfg(test)]
mod testler {
    use super::*;

    #[test]
    fn oui_listesi_okunur() {
        let yol = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../veri/oui.csv");
        if !yol.exists() {
            return; // liste indirilmemişse atla
        }
        let oui = oui_yukle(&yol);
        assert!(oui.len() > 30_000, "{} kayıt", oui.len());
        for (onek, beklenen) in [([0x00, 0x03, 0x93], "Apple"), ([0x00, 0x21, 0x9b], "")] {
            let ad = oui.get(&onek).cloned().unwrap_or_default();
            println!("{} → {ad}", mac_yazi(&[onek[0], onek[1], onek[2], 0, 0, 0]));
            assert!(ad.starts_with(beklenen));
        }
        println!("toplam {} üretici öneki", oui.len());
    }
}
