//! Yerel Unix soketi üzerinden JSON API. Mac uygulaması ve `kalkan durum` bunu kullanır.
//!
//! Protokol: istemci tek satır JSON gönderir, sunucu tek satır JSON cevap verir.
//!   {"komut":"durum"}
//!   {"komut":"uyarilar","saat":24}
//!   {"komut":"akislar","adet":200,"sadece_anomali":false}
//!   {"komut":"zaman_serisi","dakika":60}
//!   {"komut":"izin_ver","kaynak":"1.2.3.4","tur":"Port taraması şüphesi"}   "bu normal"
//!   {"komut":"izin_kaldir","kaynak":"1.2.3.4","tur":"..."}
//!   {"komut":"izinler"}
//!   {"komut":"engelle","ip":"1.2.3.4","sure_dk":60,"neden":"Port taraması şüphesi"}   sure_dk 0 = kalıcı
//!   {"komut":"engel_kaldir","ip":"1.2.3.4"}
//!   {"komut":"engeller"}
//!   {"komut":"gizli_mod","acik":true,"bonjour":false}   yerel ağda görünmezlik
//!   {"komut":"portlar"}   bu Mac'te dinleyen servisler
//!   {"komut":"cihazlar"}  yerel ağda görülen cihazlar (ARP + mDNS)
//!   {"komut":"tarama_baslat"}  kendi ağını aktif tara (öz-denetim)
//!   {"komut":"tarama_durum"}   tarama ilerlemesi ve sonucu
//!   {"komut":"olaylar","saat":24,"kategori":"kural","adet":200}   olay günlüğü (kategori boşsa hepsi)
//!
//! Soket sadece root ve yönetici (admin) grubuna açıktır.

use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use cekirdek::uyari::{self, AnomaliAkisi};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::engel::Engelleyici;
use crate::tarama::Tarayici;
use crate::motor::{Durum, Izinler, log};

#[derive(Deserialize)]
struct Istek {
    komut: String,
    #[serde(default = "varsayilan_saat")]
    saat: u64,
    #[serde(default = "varsayilan_adet")]
    adet: u32,
    #[serde(default)]
    sadece_anomali: bool,
    #[serde(default = "varsayilan_dakika")]
    dakika: u64,
    #[serde(default)]
    kaynak: String,
    #[serde(default)]
    tur: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    sure_dk: u64,
    #[serde(default)]
    neden: String,
    #[serde(default)]
    acik: bool,
    #[serde(default)]
    bonjour: bool,
    #[serde(default)]
    kategori: String,
}
fn varsayilan_saat() -> u64 { 24 }
fn varsayilan_adet() -> u32 { 200 }
fn varsayilan_dakika() -> u64 { 60 }

fn simdi_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

/// macOS'te yönetici grubu (admin) her zaman 80'dir.
const ADMIN_GID: u32 = 80;

pub fn baslat(
    soket: PathBuf,
    db_yolu: PathBuf,
    durum: Arc<Mutex<Durum>>,
    izinler: Izinler,
    engelleyici: Arc<Engelleyici>,
    cihazlar: Arc<Mutex<Vec<crate::arp::Cihaz>>>,
    tarayici: Tarayici,
) -> Result<()> {
    let _ = std::fs::remove_file(&soket);
    let dinleyici = UnixListener::bind(&soket)?;
    // Mac uygulaması (yönetici kullanıcı) bağlanabilsin, sıradan süreçler engel/izin komutu veremesin
    match std::os::unix::fs::chown(&soket, None, Some(ADMIN_GID)) {
        Ok(()) => std::fs::set_permissions(&soket, std::fs::Permissions::from_mode(0o660))?,
        Err(_) => std::fs::set_permissions(&soket, std::fs::Permissions::from_mode(0o600))?,
    }
    log(&format!("API: {}", soket.display()));
    std::thread::spawn(move || {
        for baglanti in dinleyici.incoming().flatten() {
            let (db_yolu, durum, izinler, engelleyici, cihazlar, tarayici) =
                (db_yolu.clone(), durum.clone(), izinler.clone(), engelleyici.clone(), cihazlar.clone(), tarayici.clone());
            std::thread::spawn(move || {
                let ortam = Ortam {
                    db_yolu: &db_yolu,
                    durum: &durum,
                    izinler: &izinler,
                    engelleyici: &engelleyici,
                    cihazlar: &cihazlar,
                    tarayici: &tarayici,
                };
                if let Err(e) = istemci(baglanti, &ortam) {
                    log(&format!("API istemci hatası: {e}"));
                }
            });
        }
    });
    Ok(())
}

struct Ortam<'a> {
    db_yolu: &'a Path,
    durum: &'a Mutex<Durum>,
    izinler: &'a Izinler,
    engelleyici: &'a Engelleyici,
    cihazlar: &'a Mutex<Vec<crate::arp::Cihaz>>,
    tarayici: &'a Tarayici,
}

fn istemci(akim: UnixStream, ortam: &Ortam) -> Result<()> {
    let mut okuyucu = BufReader::new(akim.try_clone()?);
    let mut yazici = akim;
    let mut satir = String::new();
    while okuyucu.read_line(&mut satir)? > 0 {
        let cevap = match serde_json::from_str::<Istek>(&satir) {
            Ok(istek) => isle(&istek, ortam).unwrap_or_else(|e| json!({"hata": e.to_string()})),
            Err(e) => json!({"hata": format!("geçersiz istek: {e}")}),
        };
        writeln!(yazici, "{cevap}")?;
        satir.clear();
    }
    Ok(())
}

fn db(db_yolu: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(db_yolu, OpenFlags::SQLITE_OPEN_READ_ONLY)?)
}

fn yazilabilir_db(db_yolu: &Path) -> Result<Connection> {
    let c = Connection::open(db_yolu)?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(c)
}

fn izin_dogrula(istek: &Istek) -> Result<()> {
    istek.kaynak.parse::<IpAddr>().map_err(|_| anyhow::anyhow!("geçersiz kaynak IP"))?;
    if !uyari::TURLER.iter().any(|(_, t, _)| *t == istek.tur) {
        anyhow::bail!("bilinmeyen uyarı türü: {}", istek.tur);
    }
    Ok(())
}

fn isle(istek: &Istek, ortam: &Ortam) -> Result<Value> {
    let (db_yolu, durum, izinler) = (ortam.db_yolu, ortam.durum, ortam.izinler);
    match istek.komut.as_str() {
        "durum" => {
            let mut v = serde_json::to_value(durum.lock().unwrap().clone())?;
            v["gizli"] = ortam.engelleyici.gizli_durumu();
            Ok(v)
        }
        "portlar" => Ok(serde_json::to_value(crate::port::tara())?),
        "olaylar" => {
            let c = db(db_yolu)?;
            let baslangic = simdi_us().saturating_sub(istek.saat * 3600 * 1_000_000);
            let mut s = c.prepare(
                "SELECT zaman_us, kategori, seviye, mesaj, ayrinti FROM olaylar
                 WHERE zaman_us >= ?1 AND (?2 = '' OR kategori = ?2)
                 ORDER BY zaman_us DESC LIMIT ?3",
            )?;
            let satirlar: Vec<Value> = s
                .query_map(rusqlite::params![baslangic as i64, istek.kategori, istek.adet], |r| {
                    let ayrinti: Option<String> = r.get(4)?;
                    Ok(json!({
                        "zaman_us": r.get::<_, i64>(0)?, "kategori": r.get::<_, String>(1)?,
                        "seviye": r.get::<_, String>(2)?, "mesaj": r.get::<_, String>(3)?,
                        "ayrinti": ayrinti.and_then(|a| serde_json::from_str::<Value>(&a).ok()),
                    }))
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(Value::Array(satirlar))
        }
        "cihazlar" => Ok(serde_json::to_value(ortam.cihazlar.lock().unwrap().clone())?),
        "tarama_baslat" => {
            // Pasif ARP'den bilinen cihaz bilgisini keşfe aktar (MAC, ad, üretici)
            let bilgi: Vec<crate::tarama::CihazIpucu> = ortam
                .cihazlar
                .lock()
                .unwrap()
                .iter()
                .flat_map(|c| c.ipler.iter().map(move |ip| (ip.clone(), Some(c.mac.clone()), c.ad.clone(), c.uretici.clone())))
                .collect();
            let yerel: Vec<std::net::IpAddr> = ortam
                .durum
                .lock()
                .unwrap()
                .yerel_ipler
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            match ortam.tarayici.baslat(bilgi, yerel) {
                Ok(()) => Ok(json!({"baslatildi": true})),
                Err(e) => Ok(json!({"baslatildi": false, "hata": e})),
            }
        }
        "tarama_durum" => Ok(serde_json::to_value(ortam.tarayici.durum())?),
        "zafiyet_surum" => Ok(json!({"surum": crate::zafiyet::surum()})),
        "gizli_mod" => {
            ortam.engelleyici.gizli_ayarla(istek.acik, istek.bonjour)?;
            Ok(json!({"tamam": true, "gizli": ortam.engelleyici.gizli_durumu()}))
        }
        "uyarilar" => {
            let baslangic = simdi_us().saturating_sub(istek.saat * 3600 * 1_000_000);
            let c = db(db_yolu)?;
            let mut s = c.prepare(
                "SELECT zaman_us, kaynak_ip, hedef_ip, hedef_port, risk, sapma, neden, surec, alan_adi
                 FROM akislar WHERE anomali = 1 AND zaman_us >= ?1",
            )?;
            let akislar = s
                .query_map([baslangic as i64], |r| {
                    Ok(AnomaliAkisi {
                        zaman_us: r.get::<_, i64>(0)? as u64,
                        kaynak: r.get::<_, String>(1)?.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
                        hedef: r.get::<_, String>(2)?.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
                        hedef_port: r.get(3)?,
                        risk: r.get::<_, Option<f64>>(4)?.unwrap_or(0.0),
                        sapma: r.get::<_, Option<f64>>(5)?.unwrap_or(0.0),
                        neden: r.get(6)?,
                        surec: r.get(7)?,
                        alan_adi: r.get(8)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(serde_json::to_value(uyari::grupla(akislar))?)
        }
        "akislar" => {
            let c = db(db_yolu)?;
            let filtre = if istek.sadece_anomali { "WHERE anomali = 1" } else { "" };
            let mut s = c.prepare(&format!(
                "SELECT zaman_us, kaynak_ip, kaynak_port, hedef_ip, hedef_port, protokol, paket, bayt,
                        sure_ms, risk, anomali, neden, surec, alan_adi
                 FROM akislar {filtre} ORDER BY zaman_us DESC LIMIT ?1"
            ))?;
            let satirlar: Vec<Value> = s
                .query_map([istek.adet], |r| {
                    Ok(json!({
                        "zaman_us": r.get::<_, i64>(0)?, "kaynak_ip": r.get::<_, String>(1)?,
                        "kaynak_port": r.get::<_, u16>(2)?, "hedef_ip": r.get::<_, String>(3)?,
                        "hedef_port": r.get::<_, u16>(4)?, "protokol": r.get::<_, String>(5)?,
                        "paket": r.get::<_, i64>(6)?, "bayt": r.get::<_, i64>(7)?,
                        "sure_ms": r.get::<_, f64>(8)?, "risk": r.get::<_, Option<f64>>(9)?,
                        "anomali": r.get::<_, i32>(10)? == 1, "neden": r.get::<_, String>(11)?,
                        "surec": r.get::<_, Option<String>>(12)?, "alan_adi": r.get::<_, Option<String>>(13)?,
                    }))
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(Value::Array(satirlar))
        }
        "zaman_serisi" => {
            // Son N dakikanın dakika dakika akış / anomali / bayt sayıları (grafik için)
            let c = db(db_yolu)?;
            let baslangic = simdi_us().saturating_sub(istek.dakika * 60 * 1_000_000);
            let mut s = c.prepare(
                "SELECT zaman_us / 60000000 AS dk, COUNT(*), SUM(anomali), SUM(bayt)
                 FROM akislar WHERE zaman_us >= ?1 GROUP BY dk ORDER BY dk",
            )?;
            let satirlar: Vec<Value> = s
                .query_map([baslangic as i64], |r| {
                    Ok(json!({
                        "dakika_us": r.get::<_, i64>(0)? * 60_000_000, "akis": r.get::<_, i64>(1)?,
                        "anomali": r.get::<_, i64>(2)?, "bayt": r.get::<_, i64>(3)?,
                    }))
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(Value::Array(satirlar))
        }
        "izin_ver" => {
            izin_dogrula(istek)?;
            let c = yazilabilir_db(db_yolu)?;
            c.execute(
                "INSERT OR REPLACE INTO izinler VALUES (?1, ?2, ?3)",
                rusqlite::params![istek.kaynak, istek.tur, simdi_us() as i64],
            )?;
            // Geçmişteki aynı uyarıları da normal say ki panelden kalksın
            let satirlar: Vec<(i64, String)> = c
                .prepare("SELECT rowid, neden FROM akislar WHERE anomali = 1 AND kaynak_ip = ?1")?
                .query_map([&istek.kaynak], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            let mut guncellenen = 0;
            for (rowid, neden) in satirlar {
                if uyari::tur_bul(&neden).0 == istek.tur {
                    c.execute(
                        "UPDATE akislar SET anomali = 0, neden = 'izinli · ' || neden WHERE rowid = ?1",
                        [rowid],
                    )?;
                    guncellenen += 1;
                }
            }
            izinler.lock().unwrap().insert((istek.kaynak.clone(), istek.tur.clone()));
            crate::gunluk::bilgi(
                crate::gunluk::Kategori::Kural,
                &format!("İzin verildi: {} · {} ({guncellenen} geçmiş akış)", istek.kaynak, istek.tur),
                json!({"islem": "izin_ver", "kaynak": istek.kaynak, "tur": istek.tur, "gecmis_akis": guncellenen}),
            );
            Ok(json!({"tamam": true, "guncellenen": guncellenen}))
        }
        "izin_kaldir" => {
            let c = yazilabilir_db(db_yolu)?;
            c.execute(
                "DELETE FROM izinler WHERE kaynak_ip = ?1 AND tur = ?2",
                rusqlite::params![istek.kaynak, istek.tur],
            )?;
            izinler.lock().unwrap().remove(&(istek.kaynak.clone(), istek.tur.clone()));
            crate::gunluk::bilgi(
                crate::gunluk::Kategori::Kural,
                &format!("İzin kaldırıldı: {} · {}", istek.kaynak, istek.tur),
                json!({"islem": "izin_kaldir", "kaynak": istek.kaynak, "tur": istek.tur}),
            );
            Ok(json!({"tamam": true}))
        }
        "izinler" => {
            let c = db(db_yolu)?;
            let satirlar: Vec<Value> = c
                .prepare("SELECT kaynak_ip, tur, zaman_us FROM izinler ORDER BY zaman_us DESC")?
                .query_map([], |r| {
                    Ok(json!({"kaynak": r.get::<_, String>(0)?, "tur": r.get::<_, String>(1)?,
                              "zaman_us": r.get::<_, i64>(2)?}))
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(Value::Array(satirlar))
        }
        "engelle" => {
            let ip: IpAddr = istek.ip.parse().map_err(|_| anyhow::anyhow!("geçersiz IP: {}", istek.ip))?;
            ortam.engelleyici.engelle(ip, istek.sure_dk, &istek.neden)?;
            Ok(json!({"tamam": true}))
        }
        "engel_kaldir" => {
            let ip: IpAddr = istek.ip.parse().map_err(|_| anyhow::anyhow!("geçersiz IP: {}", istek.ip))?;
            ortam.engelleyici.kaldir(ip, "kullanıcı")?;
            Ok(json!({"tamam": true}))
        }
        "engeller" => {
            let c = db(db_yolu)?;
            let satirlar: Vec<Value> = c
                .prepare("SELECT ip, baslangic_us, bitis_us, neden FROM engeller ORDER BY baslangic_us DESC")?
                .query_map([], |r| {
                    Ok(json!({"ip": r.get::<_, String>(0)?, "baslangic_us": r.get::<_, i64>(1)?,
                              "bitis_us": r.get::<_, i64>(2)?, "neden": r.get::<_, String>(3)?}))
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(Value::Array(satirlar))
        }
        diger => Ok(json!({"hata": format!("bilinmeyen komut: {diger}")})),
    }
}
