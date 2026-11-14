//! Hangi uygulama bağlandı? Soket → uygulama haritası (macOS libproc).
//!
//! İki saniyede bir bütün süreçlerin TCP/UDP soketleri taranır ve
//! (protokol, yerel port, uzak adres, uzak port) → uygulama adı tutulur. Bir akış
//! kapandığında uygulama bu haritadan bulunur; kapanan soketler 5 dk hatırlanır.
//! Başka kullanıcıların süreçlerini görmek için servis root olmalı.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::file_info::{ListFDs, ProcFDType, pidfdinfo};
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::libproc::proc_pid::{listpidinfo, name, pidinfo, pidpath};
use libproc::processes::{ProcFilter, pids_by_type};

const TARAMA_ARASI: Duration = Duration::from_secs(2);
const HATIRLAMA: Duration = Duration::from_secs(300);
/// Yeni bağlantı tetiklemesiyle iki tarama arasında en az bu kadar beklenir
const EN_KISA_ARA: Duration = Duration::from_millis(400);

/// (protokol, yerel port, uzak adres, uzak port)
type Anahtar = (u8, u16, IpAddr, u16);

#[derive(Default)]
struct Ic {
    soketler: HashMap<Anahtar, (Arc<str>, Instant)>,
    /// pid → uygulama adı (pid yeniden kullanılırsa diye tarama başına yenilenir)
    adlar: HashMap<i32, Arc<str>>,
}

#[derive(Clone, Default)]
pub struct SoketHaritasi(Arc<Mutex<Ic>>, Arc<(Mutex<bool>, Condvar)>);

/// macOS sistem süreçleri için anlaşılır adlar.
fn tanidik_ad(surec: &str) -> Option<&'static str> {
    Some(match surec {
        "com.apple.WebKit.Networking" => "Safari (WebKit)",
        "mDNSResponder" => "DNS (mDNSResponder)",
        "parsecd" => "Spotlight önerileri",
        "nsurlsessiond" => "Arka plan indirmeleri",
        "apsd" => "Apple bildirimleri",
        "trustd" => "Sertifika denetimi",
        "cloudd" | "bird" => "iCloud",
        "akd" | "AuthKit" => "Apple Kimliği",
        "softwareupdated" => "Yazılım güncelleme",
        "timed" | "ntpd" => "Saat eşitleme",
        "rapportd" => "Handoff / Continuity",
        "sharingd" => "AirDrop / paylaşım",
        "identityservicesd" | "imagent" => "iMessage / FaceTime",
        "locationd" => "Konum servisleri",
        "assistantd" | "siriknowledged" => "Siri",
        "storedownloadd" | "appstoreagent" => "App Store",
        "syspolicyd" => "Uygulama güvenlik denetimi (Gatekeeper)",
        "Mail" | "com.apple.MobileSMS" => return None, // zaten anlaşılır
        _ => return None,
    })
}

/// Kullanıcıya gösterilecek ad: yolundaki ilk ".app" paketi (Chrome Helper → Google Chrome),
/// yoksa süreç adı.
fn uygulama_adi(pid: i32) -> Option<String> {
    if let Ok(yol) = pidpath(pid)
        && let Some(app) = yol.split('/').find(|p| p.ends_with(".app"))
    {
        return Some(app.trim_end_matches(".app").to_string());
    }
    let ad = name(pid).ok().filter(|n| !n.is_empty())?;
    Some(tanidik_ad(&ad).map(str::to_string).unwrap_or(ad))
}

fn ip_cevir(v6_mi: bool, ina: &libproc::libproc::net_info::InSIAddr) -> IpAddr {
    // SAFETY: union; vflag hangi alanın geçerli olduğunu söylüyor
    unsafe {
        if v6_mi {
            IpAddr::V6(Ipv6Addr::from(ina.ina_6.s6_addr))
        } else {
            IpAddr::V4(Ipv4Addr::from(u32::from_be(ina.ina_46.i46a_addr4.s_addr)))
        }
    }
}

impl SoketHaritasi {
    /// Arka plan taramasını başlatır.
    pub fn baslat() -> Self {
        let h = SoketHaritasi::default();
        let h2 = h.clone();
        std::thread::spawn(move || {
            let (bayrak, sinyal) = &*h2.1;
            loop {
                h2.tara();
                std::thread::sleep(EN_KISA_ARA);
                // 2 sn bekle ya da yeni bir bağlantı başlarsa hemen tara
                let kilit = bayrak.lock().unwrap();
                let (mut kilit, _) = sinyal.wait_timeout_while(kilit, TARAMA_ARASI, |uyan| !*uyan).unwrap();
                *kilit = false;
            }
        });
        h
    }

    /// Yeni bir bağlantı başladı: soket kısa ömürlü olabilir, hemen tara.
    pub fn uyandir(&self) {
        let (bayrak, sinyal) = &*self.1;
        *bayrak.lock().unwrap() = true;
        sinyal.notify_one();
    }

    fn tara(&self) {
        let Ok(pidler) = pids_by_type(ProcFilter::All) else { return };
        let simdi = Instant::now();
        let mut bulunan: Vec<(Anahtar, i32)> = Vec::new();
        for pid in pidler {
            let pid = pid as i32;
            let Ok(bilgi) = pidinfo::<BSDInfo>(pid, 0) else { continue };
            let Ok(fdler) = listpidinfo::<ListFDs>(pid, bilgi.pbi_nfiles as usize) else { continue };
            for fd in fdler {
                if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
                    continue;
                }
                let Ok(s) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) else { continue };
                let tur = SocketInfoKind::from(s.psi.soi_kind);
                // SAFETY: soi_kind'a göre union alanı seçiliyor
                let ini = unsafe {
                    match tur {
                        SocketInfoKind::Tcp => s.psi.soi_proto.pri_tcp.tcpsi_ini,
                        SocketInfoKind::In => s.psi.soi_proto.pri_in,
                        _ => continue,
                    }
                };
                let proto = match s.psi.soi_protocol {
                    6 => 6u8,
                    17 => 17u8,
                    _ => continue,
                };
                let v6 = ini.insi_vflag & 0x2 != 0 && ini.insi_vflag & 0x1 == 0;
                let yerel_port = u16::from_be(ini.insi_lport as u16);
                let uzak_port = u16::from_be(ini.insi_fport as u16);
                let mut uzak = ip_cevir(v6, &ini.insi_faddr);
                // IPv4'ü IPv6 soketten kullanan (::ffff:a.b.c.d) bağlantılar
                if let IpAddr::V6(a) = uzak
                    && let Some(v4) = a.to_ipv4_mapped()
                {
                    uzak = IpAddr::V4(v4);
                }
                if yerel_port != 0 {
                    bulunan.push(((proto, yerel_port, uzak, uzak_port), pid));
                }
            }
        }
        let mut ic = self.0.lock().unwrap();
        let mut yeni_adlar: HashMap<i32, Arc<str>> = HashMap::new();
        for (anahtar, pid) in bulunan {
            let ad = yeni_adlar
                .entry(pid)
                .or_insert_with(|| {
                    ic.adlar.get(&pid).cloned().unwrap_or_else(|| {
                        Arc::from(uygulama_adi(pid).unwrap_or_else(|| format!("pid {pid}")))
                    })
                })
                .clone();
            ic.soketler.insert(anahtar, (ad, simdi));
        }
        ic.adlar = yeni_adlar;
        ic.soketler.retain(|_, (_, t)| simdi.duration_since(*t) < HATIRLAMA);
    }

    /// Akışın yerel tarafındaki uygulama. Bağlı soket bulunamazsa (UDP gibi bağlanmamış
    /// soketlerde) sadece yerel portla eşleşen dinleyici denenir.
    pub fn bul(&self, proto: u8, yerel_port: u16, uzak: IpAddr, uzak_port: u16) -> Option<String> {
        let ic = self.0.lock().unwrap();
        let bos4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let bos6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        ic.soketler
            .get(&(proto, yerel_port, uzak, uzak_port))
            .or_else(|| ic.soketler.get(&(proto, yerel_port, bos4, 0)))
            .or_else(|| ic.soketler.get(&(proto, yerel_port, bos6, 0)))
            .map(|(ad, _)| ad.to_string())
    }
}

#[cfg(test)]
mod testler {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn yeni_baglantinin_sahibi_bulunur() {
        let h = SoketHaritasi::baslat();
        std::thread::sleep(Duration::from_millis(300)); // ilk tarama bitsin
        let dinleyici = TcpListener::bind("127.0.0.1:0").unwrap();
        let hedef_port = dinleyici.local_addr().unwrap().port();
        let baglanti = TcpStream::connect(("127.0.0.1", hedef_port)).unwrap();
        let yerel_port = baglanti.local_addr().unwrap().port();
        h.uyandir();
        std::thread::sleep(Duration::from_millis(400));
        let ad = h.bul(6, yerel_port, "127.0.0.1".parse().unwrap(), hedef_port);
        println!("bulunan uygulama: {ad:?}");
        assert!(ad.is_some_and(|a| a.starts_with("kalkan_servis") || a.starts_with("kalkan-servis")));
    }

    #[test]
    #[ignore] // ölçüm: cargo test -p kalkan-servis --release -- --ignored --nocapture
    fn tarama_maliyeti() {
        let h = SoketHaritasi::default();
        let bas = std::time::Instant::now();
        for _ in 0..10 {
            h.tara();
        }
        let sure = bas.elapsed() / 10;
        let soket = h.0.lock().unwrap().soketler.len();
        println!("bir tarama: {sure:?}, {soket} soket; 2 sn'de bir → çekirdek payı ~%{:.2}", sure.as_secs_f64() / 2.0 * 100.0);
    }
}
