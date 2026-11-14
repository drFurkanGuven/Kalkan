//! Paket kaynakları: canlı ağ arayüzü veya pcap dosyası (test için).

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use cekirdek::paket::Baglanti;

use crate::motor::{Motor, log};

const ARAYUZ_KONTROL: Duration = Duration::from_secs(15);

fn simdi_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

/// Varsayılan rotanın arayüzü (VPN açıksa utunX, değilse genelde en0).
pub fn varsayilan_arayuz() -> Option<String> {
    let cikti = Command::new("/sbin/route").args(["-n", "get", "default"]).output().ok()?;
    String::from_utf8_lossy(&cikti.stdout)
        .lines()
        .find_map(|s| s.trim().strip_prefix("interface:").map(|a| a.trim().to_string()))
}

fn baglanti_turu(linktype: i32) -> Option<Baglanti> {
    match linktype {
        1 => Some(Baglanti::Ethernet),
        12 | 14 | 101 | 228 | 229 => Some(Baglanti::HamIp),
        0 | 108 => Some(Baglanti::Null),
        _ => None,
    }
}

/// Fiziksel yerel ağ arayüzü (Wi-Fi / Ethernet) ve ağ adresi, ör. ("en0", "192.168.1.0/24").
pub fn yerel_ag_arayuzu() -> Option<(String, String)> {
    let mut adaylar: Vec<(String, String)> = pcap::Device::list()
        .ok()?
        .into_iter()
        .filter(|d| d.name.starts_with("en") && d.flags.is_up() && d.flags.is_running())
        .filter_map(|d| {
            d.addresses.iter().find_map(|a| match (a.addr, a.netmask) {
                (std::net::IpAddr::V4(ip), Some(std::net::IpAddr::V4(maske))) if !ip.is_link_local() => {
                    let onek = u32::from(maske).count_ones();
                    let ag = std::net::Ipv4Addr::from(u32::from(ip) & u32::from(maske));
                    Some((d.name.clone(), format!("{ag}/{onek}")))
                }
                _ => None,
            })
        })
        .collect();
    adaylar.sort(); // en0 önce
    adaylar.into_iter().next()
}

/// Dinlenecek bir arayüz. `filtre` verilirse çekirdekte (BPF) uygulanır.
#[derive(Clone, PartialEq, Debug)]
struct Hedef {
    arayuz: String,
    filtre: Option<String>,
}

/// Neyi dinleyeceğiz: varsayılan rota + (VPN açıksa) fiziksel kartta sadece yerel ağ trafiği.
/// VPN açıkken yerel ağdan gelen taramalar tünele değil Wi-Fi kartına gelir; onları da görmek için.
fn dinlenecekler(sabit: Option<&str>) -> Vec<Hedef> {
    if let Some(a) = sabit {
        return vec![Hedef { arayuz: a.to_string(), filtre: None }];
    }
    let Some(varsayilan) = varsayilan_arayuz() else { return vec![] };
    let mut v = vec![Hedef { arayuz: varsayilan.clone(), filtre: None }];
    if let Some((fiziksel, ag)) = yerel_ag_arayuzu()
        && fiziksel != varsayilan
    {
        // ARP + iki ucu da yerel ağda olan paketler: tünelin şifreli paketleri (VPN sunucusuna) dışarıda kalır
        v.push(Hedef { arayuz: fiziksel, filtre: Some(format!("arp or (src net {ag} and dst net {ag})")) });
    }
    v
}

fn etiket(hedefler: &[Hedef]) -> String {
    hedefler
        .iter()
        .map(|h| if h.filtre.is_some() { format!("{} (yerel ağ)", h.arayuz) } else { h.arayuz.clone() })
        .collect::<Vec<_>>()
        .join(" + ")
}

enum Mesaj {
    Paket(Baglanti, Vec<u8>, u64),
    Hata(String, String),
}

/// Canlı izleme. `sabit_arayuz` verilmezse varsayılan rota (ve VPN açıkken yerel ağ kartı)
/// izlenir; ağ değişince (VPN açılıp kapanınca, Wi-Fi değişince) yakalama yeniden kurulur.
pub fn canli(motor: &mut Motor, sabit_arayuz: Option<&str>, dur: &Arc<AtomicBool>) -> Result<()> {
    while !dur.load(Ordering::Relaxed) {
        let hedefler = dinlenecekler(sabit_arayuz);
        if hedefler.is_empty() {
            log("İnternet bağlantısı yok, bekleniyor...");
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }
        if let Err(e) = oturum(motor, &hedefler, sabit_arayuz.is_none(), dur) {
            crate::gunluk::uyari(crate::gunluk::Kategori::Sistem, &format!("Yakalama hatası: {e}. 5 sn sonra tekrar denenecek."), serde_json::Value::Null);
            std::thread::sleep(Duration::from_secs(5));
        }
        motor.bosalt();
    }
    Ok(())
}

fn ac(h: &Hedef) -> Result<(pcap::Capture<pcap::Active>, Baglanti, i32)> {
    let mut cap = pcap::Capture::from_device(h.arayuz.as_str())?
        .promisc(false)
        .snaplen(2048) // TLS ClientHello (SNI) tam paket halinde gelsin
        .timeout(500)
        .immediate_mode(true)
        .buffer_size(4 << 20)
        .open()
        .map_err(|e| anyhow!("{e} (root yetkisi gerekiyor: sudo)"))?;
    if let Some(f) = &h.filtre {
        cap.filter(f, true)?;
    }
    let lt = cap.get_datalink().0;
    let baglanti = baglanti_turu(lt).ok_or_else(|| anyhow!("desteklenmeyen bağlantı türü {lt}"))?;
    Ok((cap, baglanti, lt))
}

/// Bir yakalama oturumu: her arayüz kendi iş parçacığında, paketler tek motora akar.
fn oturum(motor: &mut Motor, hedefler: &[Hedef], takip_et: bool, dur: &Arc<AtomicBool>) -> Result<()> {
    let oturum_dur = Arc::new(AtomicBool::new(false));
    let (gonder, al) = std::sync::mpsc::sync_channel::<Mesaj>(20_000);
    let mut iplikler = Vec::new();
    for h in hedefler {
        let (mut cap, baglanti, lt) = ac(h).map_err(|e| anyhow!("{}: {e}", h.arayuz))?;
        crate::gunluk::bilgi(
            crate::gunluk::Kategori::Ag,
            &format!(
                "Dinleniyor: {} (bağlantı türü {lt}){}",
                h.arayuz,
                h.filtre.as_ref().map(|f| format!(" · filtre: {f}")).unwrap_or_default()
            ),
            serde_json::json!({"arayuz": h.arayuz, "baglanti_turu": lt, "filtre": h.filtre}),
        );
        let (gonder, oturum_dur, ad) = (gonder.clone(), oturum_dur.clone(), h.arayuz.clone());
        iplikler.push(std::thread::spawn(move || {
            while !oturum_dur.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(p) => {
                        let ts = p.header.ts;
                        let zaman_us = ts.tv_sec as u64 * 1_000_000 + ts.tv_usec as u64;
                        if gonder.send(Mesaj::Paket(baglanti, p.data.to_vec(), zaman_us)).is_err() {
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => {
                        let _ = gonder.send(Mesaj::Hata(ad.clone(), e.to_string()));
                        break;
                    }
                }
            }
        }));
    }
    drop(gonder);
    motor.arayuz_ayarla(&etiket(hedefler));

    let mut son_tik = Instant::now();
    let mut son_kontrol = Instant::now();
    let sonuc = loop {
        if dur.load(Ordering::Relaxed) {
            break Ok(());
        }
        match al.recv_timeout(Duration::from_millis(500)) {
            Ok(Mesaj::Paket(b, veri, zaman_us)) => motor.paket(b, &veri, zaman_us),
            Ok(Mesaj::Hata(ad, e)) => break Err(anyhow!("{ad}: {e}")),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break Err(anyhow!("yakalama durdu")),
        }
        if son_tik.elapsed() >= Duration::from_secs(1) {
            motor.tik(simdi_us());
            son_tik = Instant::now();
        }
        if takip_et && son_kontrol.elapsed() >= ARAYUZ_KONTROL {
            son_kontrol = Instant::now();
            let yeni = dinlenecekler(None);
            if !yeni.is_empty() && yeni != hedefler {
                crate::gunluk::bilgi(
                    crate::gunluk::Kategori::Ag,
                    &format!("Ağ değişti: {} → {}", etiket(hedefler), etiket(&yeni)),
                    serde_json::json!({"eski": etiket(hedefler), "yeni": etiket(&yeni)}),
                );
                break Ok(());
            }
        }
    };
    oturum_dur.store(true, Ordering::Relaxed);
    drop(al); // gönderenler engelde kalmasın
    for i in iplikler {
        let _ = i.join();
    }
    sonuc
}

/// pcap dosyasını canlıymış gibi oynatır (root gerektirmez; test ve demo için).
/// Zaman olarak paket zaman damgaları kullanılır.
pub fn oynat(motor: &mut Motor, yol: &Path, dur: &Arc<AtomicBool>) -> Result<()> {
    motor.arayuz_ayarla(&format!("dosya:{}", yol.file_name().unwrap_or_default().to_string_lossy()));
    let dosya = std::fs::File::open(yol)?;
    let mut okuyucu = pcap_file::pcap::PcapReader::new(std::io::BufReader::new(dosya))?;
    let baglanti = cekirdek::kaynak::baglanti_turu(okuyucu.header().datalink)
        .ok_or_else(|| anyhow!("desteklenmeyen bağlantı türü"))?;
    let mut son_tik_us = 0u64;
    while let Some(p) = okuyucu.next_packet() {
        if dur.load(Ordering::Relaxed) {
            break;
        }
        let p = p?;
        let zaman_us = p.timestamp().as_micros() as u64;
        motor.paket(baglanti, p.data(), zaman_us);
        if zaman_us.saturating_sub(son_tik_us) >= 1_000_000 {
            motor.tik(zaman_us);
            son_tik_us = zaman_us;
        }
    }
    motor.bosalt();
    motor.tik(son_tik_us);
    Ok(())
}

#[cfg(test)]
mod testler {
    #[test]
    fn yerel_ag_arayuzu_ve_hedefler() {
        // Makineye bağlı; sadece çökmediğini ve makul çıktı verdiğini gösterir
        let ag = super::yerel_ag_arayuzu();
        println!("yerel ağ: {ag:?}");
        println!("dinlenecekler: {:?}", super::dinlenecekler(None));
        if let Some((ad, cidr)) = ag {
            assert!(ad.starts_with("en"));
            assert!(cidr.contains('/'));
        }
    }
}
