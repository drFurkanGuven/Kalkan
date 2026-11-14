//! Olay günlüğü: servisin yaptığı ve gördüğü her önemli şeyin sistematik kaydı.
//!
//! Akışlar `akislar` tablosunda; buradaki `olaylar` tablosu ise "ne oldu" sorusunun
//! cevabı: servis başladı, ağ değişti, model eğitildi, bir IP engellendi, süresi doldu,
//! izin verildi, gizli mod açıldı, ağa yeni cihaz katıldı, uyarı çıktı...
//!
//! Her olay: zaman, kategori, seviye, okunur mesaj ve yapılandırılmış ayrıntı (JSON).
//! Aynı mesaj metin loguna da (stderr → /Library/Logs/Kalkan/servis.log) yazılır.
//! 90 gün saklanır.

use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rusqlite::{Connection, params};
use serde_json::Value;

use crate::motor::log;

const SAKLAMA_US: u64 = 90 * 24 * 3600 * 1_000_000;

static DB: OnceLock<Mutex<Connection>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub enum Kategori {
    /// servis, model, yakalama
    Sistem,
    /// arayüz, ağ geçidi, cihazlar, portlar
    Ag,
    /// engel, izin, gizli mod
    Kural,
    /// tespit edilen şüpheli durumlar
    Uyari,
}

#[derive(Clone, Copy, Debug)]
pub enum Seviye {
    Bilgi,
    Uyari,
    Kritik,
}

impl Kategori {
    pub fn ad(self) -> &'static str {
        match self {
            Kategori::Sistem => "sistem",
            Kategori::Ag => "ag",
            Kategori::Kural => "kural",
            Kategori::Uyari => "uyari",
        }
    }
}

impl Seviye {
    pub fn ad(self) -> &'static str {
        match self {
            Seviye::Bilgi => "bilgi",
            Seviye::Uyari => "uyari",
            Seviye::Kritik => "kritik",
        }
    }
}

fn simdi_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

/// Günlüğü veritabanına bağlar. Çağrılmazsa (testler) olaylar sadece metin loguna gider.
pub fn baslat(db_yolu: &Path) -> Result<()> {
    if let Some(dizin) = db_yolu.parent() {
        std::fs::create_dir_all(dizin)?;
    }
    let c = Connection::open(db_yolu)?;
    c.busy_timeout(Duration::from_secs(5))?;
    c.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS olaylar (
            zaman_us INTEGER, kategori TEXT, seviye TEXT, mesaj TEXT, ayrinti TEXT);
         CREATE INDEX IF NOT EXISTS ix_olay_zaman ON olaylar(zaman_us);
         CREATE INDEX IF NOT EXISTS ix_olay_kategori ON olaylar(kategori, zaman_us);",
    )?;
    let _ = DB.set(Mutex::new(c));
    Ok(())
}

/// Bir olayı kaydet (ve metin loguna yaz).
pub fn olay(kategori: Kategori, seviye: Seviye, mesaj: &str, ayrinti: Value) {
    log(mesaj);
    let Some(db) = DB.get() else { return };
    let ayrinti = if ayrinti.is_null() { None } else { Some(ayrinti.to_string()) };
    if let Err(e) = db.lock().unwrap().execute(
        "INSERT INTO olaylar VALUES (?1, ?2, ?3, ?4, ?5)",
        params![simdi_us() as i64, kategori.ad(), seviye.ad(), mesaj, ayrinti],
    ) {
        log(&format!("Günlüğe yazılamadı: {e}"));
    }
}

/// Kısayollar
pub fn bilgi(k: Kategori, mesaj: &str, ayrinti: Value) {
    olay(k, Seviye::Bilgi, mesaj, ayrinti);
}
pub fn uyari(k: Kategori, mesaj: &str, ayrinti: Value) {
    olay(k, Seviye::Uyari, mesaj, ayrinti);
}
pub fn kritik(k: Kategori, mesaj: &str, ayrinti: Value) {
    olay(k, Seviye::Kritik, mesaj, ayrinti);
}

/// 90 günden eski olayları sil (saatlik bakımdan çağrılır).
pub fn temizle() {
    if let Some(db) = DB.get() {
        let _ = db.lock().unwrap().execute(
            "DELETE FROM olaylar WHERE zaman_us < ?1",
            [simdi_us().saturating_sub(SAKLAMA_US) as i64],
        );
    }
}
