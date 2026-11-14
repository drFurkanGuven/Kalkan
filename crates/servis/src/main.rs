//! kalkan-servis: arka planda çalışan ağ izleme servisi.
//!
//! İlk çalıştırmada öğrenme moduna girer (varsayılan 24 saat): normal trafiği
//! kaydeder, sonra modeli kendisi eğitir ve izlemeye geçer. Model haftada bir
//! son 7 günün normal trafiğiyle güncellenir.
//!
//!   sudo kalkan-servis                        canlı izleme (launchd bunu çalıştırır)
//!   kalkan-servis --oynat kayit.pcap --veri-dizini /tmp/k --ogrenme-suresi 10m   test

mod api;
mod arp;
mod engel;
mod gunluk;
mod motor;
mod port;
mod surecler;
mod tarama;
mod zafiyet;
mod yakalama;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use clap::Parser;

use motor::{Motor, log};

#[derive(Parser)]
#[command(name = "kalkan-servis", version, about = "Kalkan ağ izleme servisi")]
struct Arg {
    /// Model, veritabanı ve soketin tutulduğu klasör
    #[arg(long, default_value = "/Library/Application Support/Kalkan")]
    veri_dizini: PathBuf,
    /// Belirli bir arayüzü dinle (verilmezse varsayılan rota takip edilir)
    #[arg(long)]
    arayuz: Option<String>,
    /// Canlı yerine bir pcap dosyasını oynat (test için, root gerekmez)
    #[arg(long)]
    oynat: Option<PathBuf>,
    /// Oynatma bitince API için açık kal (Ctrl+C ile çık)
    #[arg(long)]
    bekle: bool,
    /// API soketi (verilmezse veri dizininde kalkan.sock). macOS'ta yol en fazla 103 karakter.
    #[arg(long)]
    soket: Option<PathBuf>,
    /// Öğrenme süresi: 30m, 2h, 24h, 3d
    #[arg(long, default_value = "24h")]
    ogrenme_suresi: String,
    /// ARP izleme için ağ geçidini elle ver (test; verilmezse sistemden okunur)
    #[arg(long, hide = true)]
    arp_gecit: Option<std::net::Ipv4Addr>,
}

fn sure_coz(s: &str) -> Result<u64> {
    let (sayi, birim) = s.split_at(s.trim_end_matches(|c: char| c.is_alphabetic()).len());
    let n: u64 = sayi.parse()?;
    let saniye = match birim {
        "s" | "" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => bail!("geçersiz süre birimi: {birim} (s, m, h, d)"),
    };
    Ok(saniye * 1_000_000)
}

fn main() -> Result<()> {
    let arg = Arg::parse();
    let dur = Arc::new(AtomicBool::new(false));
    {
        let dur = dur.clone();
        ctrlc::set_handler(move || dur.store(true, Ordering::Relaxed))?;
    }

    // Günlük motordan önce: açılıştaki olaylar (model yüklendi vb.) da kaydedilsin
    gunluk::baslat(&arg.veri_dizini.join("kalkan.db"))?;
    zafiyet::baslat(&arg.veri_dizini.join("kev.json"));
    let mut motor = Motor::new(&arg.veri_dizini, sure_coz(&arg.ogrenme_suresi)?, arg.arp_gecit)?;
    let soket = arg.soket.clone().unwrap_or_else(|| arg.veri_dizini.join("kalkan.sock"));
    let db_yolu = arg.veri_dizini.join("kalkan.db");
    let engelleyici = engel::Engelleyici::baslat(&db_yolu);
    {
        let mut d = motor.durum.lock().unwrap();
        d.engelleme = engelleyici.etkin();
        d.yerel_ipler = engel::yerel_ipler().iter().map(|ip| ip.to_string()).collect();
    }
    port::baslat(&db_yolu, motor.durum.clone());
    let tarayici = tarama::Tarayici::default();
    api::baslat(soket, db_yolu, motor.durum.clone(), motor.izinler.clone(), engelleyici.clone(), motor.cihazlar.clone(), tarayici)?;
    gunluk::bilgi(
        gunluk::Kategori::Sistem,
        &format!("Kalkan servisi başladı · veri: {}", arg.veri_dizini.display()),
        serde_json::json!({"surum": env!("CARGO_PKG_VERSION"), "ogrenme_suresi": arg.ogrenme_suresi}),
    );

    match &arg.oynat {
        Some(yol) => {
            yakalama::oynat(&mut motor, yol, &dur)?;
            let d = motor.durum.lock().unwrap().clone();
            log(&format!("Oynatma bitti: {} akış, {} anomali, mod: {}", d.toplam_akis, d.anomali, d.mod_));
            if arg.bekle {
                log("API açık, çıkmak için Ctrl+C.");
                while !dur.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }
        None => yakalama::canli(&mut motor, arg.arayuz.as_deref(), &dur)?,
    }
    motor.bosalt();
    engelleyici.kapat();
    gunluk::bilgi(gunluk::Kategori::Sistem, "Kalkan servisi durdu.", serde_json::Value::Null);
    Ok(())
}
