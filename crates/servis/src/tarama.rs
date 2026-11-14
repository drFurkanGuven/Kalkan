//! Ağ öz-denetimi: kendi yerel ağını aktif tarayıp zayıf noktalarını gösterir.
//!
//! Savunma amaçlıdır: "bir saldırgan ağıma baksa ne görürdü?" sorusunu, saldırgandan
//! önce sen cevaplayıp açıkları kapatırsın. Üç aşama:
//!   1. Cihaz keşfi: alt ağdaki IP'lere TCP ile dokunup ayakta olanları bulur.
//!   2. Port taraması: her cihazda yaygın portları TCP ile dener.
//!   3. Rapor: açık portları servis adı, risk ve kapatma önerisiyle sunar.
//!
//! Yalnızca bu Mac'in bulunduğu yerel alt ağı tarar (en çok 1022 adres). Dışarıdaki
//! hiçbir adrese dokunmaz. Sadece TCP bağlantısı kurar (root gerektirmez), paket üretmez.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Pasif ARP'den gelen cihaz ipucu: (ip, mac, ad, üretici)
pub type CihazIpucu = (String, Option<String>, Option<String>, Option<String>);

use crate::gunluk::{self, Kategori};

/// Cihaz keşfinde denenen portlar (biri bile cevap verirse cihaz ayakta sayılır).
const KESIF_PORTLARI: &[u16] = &[80, 443, 22, 445, 139, 53, 5000, 7000, 8080, 62078, 3389, 9100];

/// Port taramasında denenen yaygın portlar.
const TARAMA_PORTLARI: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 515, 548, 554,
    587, 631, 636, 873, 902, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2222,
    3000, 3128, 3283, 3306, 3389, 3689, 4444, 5000, 5001, 5432, 5555, 5601, 5900, 5901, 6379, 7000,
    7070, 8000, 8008, 8080, 8081, 8083, 8086, 8096, 8123, 8181, 8443, 8554, 8888, 9000, 9090, 9100,
    9200, 9300, 10000, 11211, 27017, 32400, 49152, 51820, 62078,
];

const KESIF_ZAMAN_ASIMI: Duration = Duration::from_millis(400);
const TARAMA_ZAMAN_ASIMI: Duration = Duration::from_millis(500);
const IPLIK: usize = 128;
const EN_FAZLA_ADRES: u32 = 1022;

fn simdi_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

#[derive(Clone, Debug, Serialize)]
pub struct AcikPort {
    pub port: u16,
    pub servis: String,
    pub seviye: &'static str,
    pub oneri: String,
    /// Servisin kendi duyurduğu ürün/sürüm bilgisi (banner), varsa
    pub surum: Option<String>,
    /// Sürümle ilgili güvenlik notu (bariz riskli durumlar), varsa
    pub surum_notu: Option<String>,
    /// Bu ürün için CISA KEV'de aktif sömürülen açıklar (sürüm bazlı değil)
    pub cveler: Vec<crate::zafiyet::CveKayit>,
}

/// HTTP isteği gönderip "Server:" başlığı okunacak portlar.
const HTTP_PORTLARI: &[u16] = &[80, 81, 591, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8083, 8086, 8123, 8181, 8888, 9000, 9090, 32400];

/// Açık bir servisin banner'ını (karşılama/sürüm bilgisi) okur. İçeri girmeye çalışmaz:
/// sadece servisin bağlantıda kendiliğinden ya da basit bir istek sonrası söylediğini okur.
fn banner_al(ip: Ipv4Addr, port: u16) -> Option<String> {
    let mut akim = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), Duration::from_millis(700)).ok()?;
    akim.set_read_timeout(Some(Duration::from_millis(900))).ok();
    akim.set_write_timeout(Some(Duration::from_millis(500))).ok();
    if HTTP_PORTLARI.contains(&port) {
        let istek = format!("HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Kalkan-denetim\r\n\r\n");
        akim.write_all(istek.as_bytes()).ok()?;
    }
    let mut tampon = [0u8; 1024];
    let n = akim.read(&mut tampon).ok()?;
    if n == 0 {
        return None;
    }
    let ham = String::from_utf8_lossy(&tampon[..n]);
    banner_coz(port, &ham)
}

/// Ham banner'dan kısa, okunur bir ürün/sürüm metni çıkarır. Yalnızca basılabilir
/// ASCII tutulur: Telnet gibi ikili anlaşma (0xFF...) gönderen servisler çöp göstermez.
fn banner_coz(port: u16, ham: &str) -> Option<String> {
    // En az birkaç anlamlı harf/rakam içermeyen (ör. Telnet anlaşma baytları) banner'ı ele.
    let temiz = |s: &str| -> Option<String> {
        let t: String = s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(80).collect();
        let t = t.trim().to_string();
        (t.chars().filter(|c| c.is_ascii_alphanumeric()).count() >= 2).then_some(t)
    };
    if HTTP_PORTLARI.contains(&port) {
        // "Server: nginx/1.18.0" başlığı
        for satir in ham.lines() {
            if let Some(d) = satir.strip_prefix("Server:").or_else(|| satir.strip_prefix("server:"))
                && let Some(d) = temiz(d)
            {
                return Some(d);
            }
        }
        // sunucu başlığı yoksa ilk durum satırı (HTTP/1.1 200 ...)
        return ham.lines().next().and_then(temiz);
    }
    // SSH-2.0-OpenSSH_9.6, 220 ProFTPD, +OK Dovecot, * OK IMAP ...
    ham.lines().next().and_then(temiz)
}

/// Banner'a göre bariz güvenlik notu (uydurma CVE yok; sadece net durumlar).
fn surum_notu(port: u16, surum: &Option<String>) -> Option<String> {
    let s = surum.as_deref().unwrap_or("").to_lowercase();
    if port == 23 {
        return Some("Telnet şifresizdir; kapatıp SSH kullan.".into());
    }
    if port == 21 && !s.contains("ssl") && !s.contains("tls") {
        return Some("FTP genelde şifresizdir; SFTP'ye geçmeyi düşün.".into());
    }
    // Çok eski OpenSSH (7.x ve altı): bilinen çok sayıda zafiyet
    if let Some(v) = s.strip_prefix("ssh-2.0-openssh_").and_then(|r| r.split(|c: char| !c.is_ascii_digit() && c != '.').next())
        && let Some(ana) = v.split('.').next().and_then(|n| n.parse::<u32>().ok())
        && ana < 8
    {
        return Some(format!("Eski OpenSSH ({v}); güncellemeyi düşün."));
    }
    None
}

#[derive(Clone, Debug, Serialize)]
pub struct TaramaCihaz {
    pub ip: String,
    pub mac: Option<String>,
    pub ad: Option<String>,
    pub uretici: Option<String>,
    pub bu_mac: bool,
    pub portlar: Vec<AcikPort>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TaramaDurumu {
    pub calisiyor: bool,
    /// "", "cihaz keşfi", "port taraması", "bitti", "hata: ..."
    pub asama: String,
    /// 0..100
    pub ilerleme: u32,
    pub baslangic_us: u64,
    pub bitis_us: u64,
    pub ag: Option<String>,
    pub taranan_adres: u32,
    pub cihazlar: Vec<TaramaCihaz>,
}

#[derive(Clone, Default)]
pub struct Tarayici {
    durum: Arc<Mutex<TaramaDurumu>>,
    calisiyor: Arc<AtomicBool>,
}

/// Bir işi IPLIK kadar iş parçacığıyla paralel yürütür, sonuçları toplar.
fn paralel<T: Send + Sync, R: Send>(isler: &[T], f: impl Fn(&T) -> Option<R> + Send + Sync) -> Vec<R> {
    let sira = AtomicUsize::new(0);
    let sonuc = Mutex::new(Vec::new());
    let iplik = IPLIK.min(isler.len().max(1));
    std::thread::scope(|s| {
        for _ in 0..iplik {
            let (sira, sonuc, f) = (&sira, &sonuc, &f);
            s.spawn(move || {
                loop {
                    let i = sira.fetch_add(1, Ordering::Relaxed);
                    let Some(is) = isler.get(i) else { break };
                    if let Some(r) = f(is) {
                        sonuc.lock().unwrap().push(r);
                    }
                }
            });
        }
    });
    sonuc.into_inner().unwrap()
}

/// TCP ile dokun: bağlanırsa veya reddedilirse (RST) hedef ayakta demektir.
fn tcp_dokun(ip: Ipv4Addr, port: u16, zaman_asimi: Duration) -> Option<bool> {
    match TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), zaman_asimi) {
        Ok(_) => Some(true),                  // port açık
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(false), // kapalı ama cihaz var
        Err(_) => None,                       // zaman aşımı / ulaşılamaz
    }
}

/// "192.168.1.0/24" → taranacak host IP'leri (ağ ve yayın adresi hariç, en çok 1022).
fn ag_hostlari(cidr: &str) -> Option<(u32, u32)> {
    let (ag, onek) = cidr.split_once('/')?;
    let taban = u32::from(ag.parse::<Ipv4Addr>().ok()?);
    let onek: u32 = onek.parse().ok()?;
    if onek >= 31 {
        return Some((taban, taban)); // tek adres
    }
    let host_sayisi = (1u32 << (32 - onek)).saturating_sub(2);
    Some((taban + 1, taban + 1 + host_sayisi.min(EN_FAZLA_ADRES)))
}

impl Tarayici {
    pub fn durum(&self) -> TaramaDurumu {
        self.durum.lock().unwrap().clone()
    }

    /// Taramayı arka planda başlatır. `cihaz_bilgisi`: pasif ARP'den (ip → (mac, ad, üretici)).
    pub fn baslat(&self, cihaz_bilgisi: Vec<CihazIpucu>, yerel: Vec<IpAddr>) -> Result<(), String> {
        if self.calisiyor.swap(true, Ordering::SeqCst) {
            return Err("Tarama zaten çalışıyor".into());
        }
        let Some((_arayuz, cidr)) = crate::yakalama::yerel_ag_arayuzu() else {
            self.calisiyor.store(false, Ordering::SeqCst);
            return Err("Yerel ağ (Wi-Fi / Ethernet) bulunamadı".into());
        };
        let (durum, calisiyor) = (self.durum.clone(), self.calisiyor.clone());
        std::thread::spawn(move || {
            let sonuc = Self::yurut(&durum, &cidr, &cihaz_bilgisi, &yerel);
            let mut d = durum.lock().unwrap();
            d.calisiyor = false;
            d.bitis_us = simdi_us();
            if let Err(e) = sonuc {
                d.asama = format!("hata: {e}");
            } else {
                d.asama = "bitti".into();
                d.ilerleme = 100;
            }
            let cihaz = d.cihazlar.len();
            let acik = d.cihazlar.iter().map(|c| c.portlar.len()).sum::<usize>();
            drop(d);
            gunluk::bilgi(
                Kategori::Ag,
                &format!("Ağ taraması bitti: {cihaz} cihaz, {acik} açık port"),
                serde_json::json!({"cihaz": cihaz, "acik_port": acik, "ag": cidr}),
            );
            calisiyor.store(false, Ordering::SeqCst);
        });
        Ok(())
    }

    fn yurut(
        durum: &Mutex<TaramaDurumu>,
        cidr: &str,
        cihaz_bilgisi: &[CihazIpucu],
        yerel: &[IpAddr],
    ) -> Result<(), String> {
        let (bas, son) = ag_hostlari(cidr).ok_or("Alt ağ çözümlenemedi")?;
        gunluk::bilgi(Kategori::Ag, &format!("Ağ taraması başladı: {cidr}"), serde_json::json!({"ag": cidr}));
        {
            let mut d = durum.lock().unwrap();
            *d = TaramaDurumu {
                calisiyor: true,
                asama: "cihaz keşfi".into(),
                baslangic_us: simdi_us(),
                ag: Some(cidr.to_string()),
                taranan_adres: son - bas,
                ..Default::default()
            };
        }

        // 1) Cihaz keşfi
        let adresler: Vec<Ipv4Addr> = (bas..son).map(Ipv4Addr::from).collect();
        let ilerleme_sayac = AtomicUsize::new(0);
        let toplam = adresler.len().max(1);
        let ayakta: Vec<Ipv4Addr> = paralel(&adresler, |&ip| {
            let mut var = false;
            for &p in KESIF_PORTLARI {
                if let Some(acik) = tcp_dokun(ip, p, KESIF_ZAMAN_ASIMI) {
                    var = true;
                    if acik {
                        break;
                    }
                }
            }
            let n = ilerleme_sayac.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_multiple_of(8) {
                durum.lock().unwrap().ilerleme = (n * 40 / toplam) as u32;
            }
            var.then_some(ip)
        });

        // pasif ARP'de görülenleri ve bu Mac'i de ayakta say
        let bilinen: std::collections::HashMap<Ipv4Addr, &CihazIpucu> =
            cihaz_bilgisi.iter().filter_map(|c| c.0.parse().ok().map(|ip| (ip, c))).collect();
        let mut hedefler: Vec<Ipv4Addr> = ayakta.clone();
        for ip in bilinen.keys() {
            if !hedefler.contains(ip) {
                hedefler.push(*ip);
            }
        }
        hedefler.sort();
        let yerel4: std::collections::HashSet<Ipv4Addr> =
            yerel.iter().filter_map(|ip| if let IpAddr::V4(v) = ip { Some(*v) } else { None }).collect();

        // 2) Port taraması: (ip, port) çiftlerini paralel tara
        durum.lock().unwrap().asama = "port taraması".into();
        let isler: Vec<(Ipv4Addr, u16)> =
            hedefler.iter().flat_map(|&ip| TARAMA_PORTLARI.iter().map(move |&p| (ip, p))).collect();
        let is_sayac = AtomicUsize::new(0);
        let is_toplam = isler.len().max(1);
        let acik: Vec<(Ipv4Addr, u16)> = paralel(&isler, |&(ip, port)| {
            let sonuc = tcp_dokun(ip, port, TARAMA_ZAMAN_ASIMI);
            let n = is_sayac.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_multiple_of(16) {
                durum.lock().unwrap().ilerleme = 40 + (n * 60 / is_toplam) as u32;
            }
            matches!(sonuc, Some(true)).then_some((ip, port))
        });

        // 2b) Açık portların banner'larını (sürüm bilgisi) oku
        durum.lock().unwrap().asama = "sürüm okuma".into();
        let bannerlar: std::collections::HashMap<(Ipv4Addr, u16), String> = paralel(&acik, |&(ip, port)| {
            banner_al(ip, port).map(|b| ((ip, port), b))
        })
        .into_iter()
        .collect();

        // 3) Rapor: ip başına açık portları topla, servis kataloğuyla etiketle
        let mut cihaz_port: std::collections::BTreeMap<Ipv4Addr, Vec<u16>> = Default::default();
        for (ip, port) in acik {
            cihaz_port.entry(ip).or_default().push(port);
        }
        for ip in &hedefler {
            cihaz_port.entry(*ip).or_default();
        }
        let cihazlar: Vec<TaramaCihaz> = cihaz_port
            .into_iter()
            .filter(|(ip, portlar)| !portlar.is_empty() || ayakta.contains(ip) || bilinen.contains_key(ip))
            .map(|(ip, mut portlar)| {
                portlar.sort_unstable();
                let bilgi = bilinen.get(&ip);
                TaramaCihaz {
                    ip: ip.to_string(),
                    mac: bilgi.and_then(|b| b.1.clone()),
                    ad: bilgi.and_then(|b| b.2.clone()),
                    uretici: bilgi.and_then(|b| b.3.clone()),
                    bu_mac: yerel4.contains(&ip),
                    portlar: portlar
                        .into_iter()
                        .map(|p| {
                            let (servis, seviye, oneri) = crate::port::bilinen_port(p)
                                .map(|(a, s, o)| (a.to_string(), s, o))
                                .unwrap_or_else(|| ("Bilinmeyen servis".into(), "orta", String::new()));
                            let surum = bannerlar.get(&(ip, p)).cloned();
                            let surum_notu = surum_notu(p, &surum);
                            let cveler = surum.as_deref().map(crate::zafiyet::eslesen).unwrap_or_default();
                            AcikPort { port: p, servis, seviye, oneri, surum, surum_notu, cveler }
                        })
                        .collect(),
                }
            })
            .collect();

        let mut d = durum.lock().unwrap();
        d.cihazlar = cihazlar;
        Ok(())
    }
}

#[cfg(test)]
mod banner_test {
    #[test]
    fn telnet_cop_gostermez() {
        // Telnet IAC anlaşma baytları: 0xFF 0xFD 0x18 ...
        let ham = String::from_utf8_lossy(&[0xff, 0xfd, 0x18, 0xff, 0xfd, 0x20, 0xff, 0xfd, 0x23]);
        assert_eq!(super::banner_coz(23, &ham), None);
        // Gerçek sürüm okunur
        assert_eq!(super::banner_coz(22, "SSH-2.0-OpenSSH_9.4\r\n"), Some("SSH-2.0-OpenSSH_9.4".into()));
        assert_eq!(super::banner_coz(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"), Some("nginx/1.18.0".into()));
    }
}
