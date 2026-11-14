//! Açık port denetimi: bu Mac'te hangi servisler dinliyor, hangileri ağdan erişilebilir?
//!
//! Dakikada bir taranır. Ağa yeni bir TCP portu açılırsa (biri Uzaktan Girişi açtı,
//! bir geliştirme sunucusu tüm ağa açıldı ya da bir arka kapı dinlemeye başladı)
//! uyarı yazılır. İlk taramada var olanlar sessizce "bilinen" sayılır.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::motor::{Durum, log};

const TARAMA_ARASI: Duration = Duration::from_secs(60);
/// Bunun üstü geçici (ephemeral) port: her açılışta değişir, süreç adıyla tanınır
const GECICI_PORT: u16 = 49152;

#[derive(Clone, Debug, Serialize)]
pub struct Port {
    pub proto: &'static str,
    pub port: u16,
    /// dinlediği adres: "*", "127.0.0.1", "192.168.1.5" ...
    pub adres: String,
    pub surec: String,
    pub pid: u32,
    pub kullanici: String,
    /// yerel ağdan (veya internetten) erişilebilir mi
    pub disari_acik: bool,
    pub ad: String,
    /// "yuksek" | "orta" | "dusuk"
    pub seviye: &'static str,
    pub oneri: String,
}

const PAYLASMA: &str = "Sistem Ayarları → Genel → Paylaşma";

/// (port, ad, seviye, öneri). Öneri boşsa sistem servisi, dokunmaya gerek yok.
pub fn bilinen_port(port: u16) -> Option<(&'static str, &'static str, String)> {
    let p = |ayar: &str| format!("Kullanmıyorsan kapat: {PAYLASMA} → {ayar}");
    Some(match port {
        22 => ("Uzaktan Giriş (SSH)", "yuksek", p("Uzaktan Giriş")),
        5900 => ("Ekran Paylaşımı (VNC)", "yuksek", p("Ekran Paylaşımı")),
        3283 => ("Uzaktan Yönetim (ARD)", "yuksek", p("Uzaktan Yönetim")),
        445 => ("Dosya Paylaşımı (SMB)", "yuksek", p("Dosya Paylaşımı")),
        548 => ("Dosya Paylaşımı (AFP)", "yuksek", p("Dosya Paylaşımı")),
        139 => ("NetBIOS dosya paylaşımı", "yuksek", p("Dosya Paylaşımı")),
        21 => ("FTP sunucusu", "yuksek", "Şifresiz dosya aktarımı; kapatman önerilir".into()),
        23 => ("Telnet", "yuksek", "Şifresiz uzaktan erişim; kesinlikle kapat".into()),
        3306 => ("MySQL veritabanı", "yuksek", "Veritabanını sadece 127.0.0.1'e bağla (bind-address)".into()),
        5432 => ("PostgreSQL veritabanı", "yuksek", "listen_addresses = 'localhost' yap".into()),
        6379 => ("Redis", "yuksek", "Şifresiz erişim riski; bind 127.0.0.1 yap".into()),
        27017 => ("MongoDB", "yuksek", "bindIp: 127.0.0.1 yap".into()),
        53 => ("DNS", "dusuk", String::new()),
        80 => ("Web arayüzü (HTTP)", "orta", "Yönlendirici/cihaz paneli olabilir; şifreli değil, güçlü parola kullan".into()),
        443 => ("Web arayüzü (HTTPS)", "dusuk", String::new()),
        8443 => ("Web yönetim arayüzü (HTTPS)", "orta", "Yönetim panosu; güçlü parola ve güncel yazılım kullan".into()),
        62078 => ("iPhone/iPad eşitleme (lockdown)", "dusuk", String::new()),
        631 => ("Yazıcı paylaşımı (CUPS)", "orta", p("Yazıcı Paylaşımı")),
        3689 => ("Müzik paylaşımı (DAAP)", "orta", p("Medya Paylaşımı")),
        7000 | 5000 => (
            "AirPlay alıcısı",
            "orta",
            "Kullanmıyorsan kapat: Sistem Ayarları → Genel → AirDrop ve Handoff → AirPlay Alıcısı".into(),
        ),
        88 => ("Kerberos (sistem)", "dusuk", String::new()),
        5353 => ("Bonjour (mDNS)", "dusuk", String::new()),
        3722 => ("Cihazlar arası (Continuity)", "dusuk", String::new()),
        3000 | 3001 | 4200 | 5173 | 8000 | 8080 | 8081 | 8501 | 8888 | 9000 => (
            "Geliştirme sunucusu",
            "orta",
            "Tüm ağa açık; sadece bu Mac'ten erişmen yetiyorsa 127.0.0.1'e bağla".into(),
        ),
        _ => return None,
    })
}

fn bilinen_surec(surec: &str) -> Option<(&'static str, &'static str)> {
    Some(match surec {
        "rapportd" => ("Handoff / Continuity (sistem)", "dusuk"),
        "sharingd" => ("AirDrop / paylaşım (sistem)", "dusuk"),
        "ControlCenter" | "AirPlayXPCHelper" => ("AirPlay (sistem)", "dusuk"),
        "mDNSResponder" => ("Bonjour (sistem)", "dusuk"),
        "identityservicesd" | "replicatord" | "remoted" | "WiFiAgent" | "netbiosd" => ("Sistem servisi", "dusuk"),
        _ => return None,
    })
}

fn yerel_mi(adres: &str) -> bool {
    adres.starts_with("127.") || adres == "::1" || adres == "[::1]" || adres.starts_with("fe80")
}

fn siniflandir(proto: &'static str, port: u16, adres: String, surec: String, pid: u32, kullanici: String) -> Port {
    let disari_acik = !yerel_mi(&adres);
    let (ad, mut seviye, oneri) = match bilinen_port(port) {
        Some((ad, s, o)) => (ad.to_string(), s, o),
        None => match bilinen_surec(&surec) {
            Some((ad, s)) => (ad.to_string(), s, String::new()),
            None => (
                format!("{surec} servisi"),
                if proto == "TCP" { "orta" } else { "dusuk" },
                "Tanımadığın bir süreçse araştır; gerekmiyorsa kapat ya da 127.0.0.1'e bağla".to_string(),
            ),
        },
    };
    if !disari_acik {
        seviye = "dusuk"; // sadece bu Mac'ten erişilebilir
    }
    Port { proto, port, adres, surec, pid, kullanici, disari_acik, ad, seviye, oneri }
}

/// `lsof -F` çıktısından dinleyen soketler.
fn lsof(argumanlar: &[&str], proto: &'static str) -> Vec<Port> {
    let Ok(c) = Command::new("/usr/sbin/lsof").args(argumanlar).output() else { return vec![] };
    let (mut pid, mut surec, mut kullanici) = (0u32, String::new(), String::new());
    let mut liste = Vec::new();
    for satir in String::from_utf8_lossy(&c.stdout).lines() {
        let (alan, deger) = satir.split_at(satir.len().min(1));
        match alan {
            "p" => pid = deger.parse().unwrap_or(0),
            "c" => surec = deger.to_string(),
            "L" => kullanici = deger.to_string(),
            "n" if !deger.contains("->") => {
                // "*:7000", "127.0.0.1:631", "[::1]:5432"
                let Some((adres, port)) = deger.rsplit_once(':') else { continue };
                let Ok(port) = port.parse::<u16>() else { continue };
                let adres = adres.trim_matches(|c| c == '[' || c == ']').to_string();
                liste.push(siniflandir(proto, port, adres, surec.clone(), pid, kullanici.clone()));
            }
            _ => {}
        }
    }
    liste
}

/// Dinleyen bütün portlar (IPv4/IPv6 tekrarları birleştirilmiş), en riskli önce.
pub fn tara() -> Vec<Port> {
    let mut hepsi = lsof(&["+c", "0", "-nP", "-iTCP", "-sTCP:LISTEN", "-FpcLn"], "TCP");
    // UDP'de çok sayıda geçici soket var: sadece tanınan portlar
    hepsi.extend(
        lsof(&["+c", "0", "-nP", "-iUDP", "-FpcLn"], "UDP")
            .into_iter()
            .filter(|p| p.port < GECICI_PORT && bilinen_port(p.port).is_some()),
    );
    // aynı (proto, port, süreç) tek satır; biri dışarı açıksa dışarı açık say
    let mut tekil: BTreeMap<(&str, u16, String), Port> = BTreeMap::new();
    for p in hepsi {
        let anahtar = (p.proto, p.port, p.surec.clone());
        match tekil.get(&anahtar) {
            Some(var) if var.disari_acik || !p.disari_acik => {}
            _ => {
                tekil.insert(anahtar, p);
            }
        }
    }
    let derece = |s: &str| match s {
        "yuksek" => 0,
        "orta" => 1,
        _ => 2,
    };
    let mut v: Vec<Port> = tekil.into_values().collect();
    v.sort_by_key(|p| (!p.disari_acik, derece(p.seviye), p.port));
    v
}

/// Uyarı ve taban kaydı için anahtar: geçici portlarda port numarası değil süreç adı önemli.
fn taban_anahtari(p: &Port) -> (String, u16, String) {
    let port = if p.port >= GECICI_PORT { 0 } else { p.port };
    (p.proto.to_string(), port, p.surec.clone())
}

fn simdi_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

/// Arka plan denetçisi: dakikada bir tarar, ağa yeni açılan TCP portu için uyarı yazar.
pub fn baslat(db_yolu: &Path, durum: Arc<Mutex<Durum>>) {
    let db_yolu: PathBuf = db_yolu.to_path_buf();
    std::thread::spawn(move || {
        loop {
            if let Err(e) = denetle(&db_yolu, &durum) {
                log(&format!("Port denetimi: {e}"));
            }
            std::thread::sleep(TARAMA_ARASI);
        }
    });
}

fn denetle(db_yolu: &Path, durum: &Mutex<Durum>) -> Result<()> {
    let c = Connection::open(db_yolu)?;
    c.busy_timeout(Duration::from_secs(5))?;
    let bilinen: HashSet<(String, u16, String)> = c
        .prepare("SELECT proto, port, surec FROM port_bilinen")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let ilk_tarama = c
        .query_row("SELECT 1 FROM ayar WHERE anahtar = 'port_taban'", [], |_| Ok(()))
        .is_err();
    let portlar = tara();
    let simdi = simdi_us();
    let mut yeni_acik = 0;
    for p in &portlar {
        let anahtar = taban_anahtari(p);
        if bilinen.contains(&anahtar) {
            continue;
        }
        c.execute(
            "INSERT OR IGNORE INTO port_bilinen VALUES (?1, ?2, ?3, ?4)",
            params![anahtar.0, anahtar.1, anahtar.2, simdi as i64],
        )?;
        if ilk_tarama || !p.disari_acik || p.proto != "TCP" {
            continue;
        }
        yeni_acik += 1;
        let neden = format!(
            "Yeni açık port: {} {} ({}, pid {}) {} · {}",
            p.proto,
            p.port,
            p.surec,
            p.pid,
            if p.adres == "*" { "tüm ağa açık".to_string() } else { format!("{} adresinde açık", p.adres) },
            p.ad
        );
        crate::gunluk::uyari(
            crate::gunluk::Kategori::Uyari,
            &format!("⚠ {neden}"),
            serde_json::json!({"tur": "Yeni açık port", "proto": p.proto, "port": p.port, "surec": p.surec, "pid": p.pid, "adres": p.adres, "seviye": p.seviye}),
        );
        let (yerel, arayuz) = {
            let d = durum.lock().unwrap();
            (
                d.yerel_ipler.iter().find(|ip| !ip.contains(':') && !ip.starts_with("127.")).cloned(),
                d.arayuz.clone(),
            )
        };
        let yerel = yerel.unwrap_or_else(|| "127.0.0.1".into());
        let risk = match p.seviye {
            "yuksek" => 20.0,
            "orta" => 6.0,
            _ => 3.0,
        };
        c.execute(
            "INSERT INTO akislar (zaman_us,kaynak_ip,kaynak_port,hedef_ip,hedef_port,protokol,paket,bayt,sure_ms,skor,sapma,risk,anomali,neden,arayuz,surec) VALUES (?1,?2,?3,?2,?3,?4,0,0,0,NULL,NULL,?5,1,?6,?7,?8)",
            params![simdi as i64, yerel, p.port, p.proto, risk, neden, arayuz, p.surec],
        )?;
        durum.lock().unwrap().anomali += 1;
    }
    if ilk_tarama {
        c.execute("INSERT OR REPLACE INTO ayar VALUES ('port_taban', '1')", [])?;
        let acik: Vec<String> =
            portlar.iter().filter(|p| p.disari_acik).map(|p| format!("{} {} ({})", p.proto, p.port, p.surec)).collect();
        crate::gunluk::bilgi(
            crate::gunluk::Kategori::Ag,
            &format!("Port denetimi: {} dinleyen servis kaydedildi ({} tanesi ağdan erişilebilir)", portlar.len(), acik.len()),
            serde_json::json!({"dinleyen": portlar.len(), "agdan_erisilebilir": acik}),
        );
    } else if yeni_acik > 0 {
        log(&format!("Port denetimi: {yeni_acik} yeni açık port"));
    }
    Ok(())
}
