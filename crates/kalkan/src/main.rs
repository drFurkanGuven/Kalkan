//! kalkan: ağ anomali izleme komut satırı aracı.
//!
//!   kalkan egit pcap/normal.pcap            normal trafikten model eğit
//!   kalkan izle --pcap pcap/dosya.pcap      dosyayı analiz et, SQLite'a yaz
//!   kalkan uyarilar                         gruplanmış uyarıları göster
//!   kalkan degerlendir normal.pcap --tarama saldiri.pcap   doğruluk ölç

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use cekirdek::kaynak::pcap_akislari;
use cekirdek::uyari::{self, AnomaliAkisi, tur_bul};
use cekirdek::{AkisKaydi, Dedektor, Pencere, Sonuc};
use chrono::{Local, TimeZone};
use clap::{Parser, Subcommand};
use rusqlite::{Connection, params};

#[derive(Parser)]
#[command(name = "kalkan", version, about = "Ağ anomali izleme")]
struct Cli {
    #[command(subcommand)]
    komut: Komut,
}

#[derive(Subcommand)]
enum Komut {
    /// Normal trafikten model eğitir (etiket gerekmez)
    Egit {
        pcapler: Vec<PathBuf>,
        #[arg(short, long, default_value = "model.json")]
        model: PathBuf,
        /// Eğitim skorlarının bu yüzdeliğinin üstü anomali sayılır
        #[arg(long, default_value_t = 99.5)]
        yuzdelik: f64,
    },
    /// pcap dosyasını analiz eder ve sonuçları SQLite'a yazar
    Izle {
        #[arg(long)]
        pcap: PathBuf,
        #[arg(short, long, default_value = "model.json")]
        model: PathBuf,
        #[arg(long, default_value = "kalkan.db")]
        db: PathBuf,
    },
    /// Veritabanındaki anomalileri uyarılara gruplayıp gösterir
    Uyarilar {
        #[arg(long, default_value = "kalkan.db")]
        db: PathBuf,
    },
    /// Çalışan servisin durumunu ve son 24 saatin uyarılarını gösterir
    Durum {
        #[arg(long, default_value = "/Library/Application Support/Kalkan/kalkan.sock")]
        soket: PathBuf,
    },
    /// Kendi yerel ağını aktif tarar (öz-denetim): cihazlar ve açık portlar
    Tara {
        #[arg(long, default_value = "/Library/Application Support/Kalkan/kalkan.sock")]
        soket: PathBuf,
    },
    /// Servisin olay günlüğü: kural değişiklikleri, ağ olayları, uyarılar, sistem
    Gunluk {
        /// Son kaç saat
        #[arg(long, default_value_t = 24)]
        saat: u64,
        /// sistem | ag | kural | uyari (verilmezse hepsi)
        #[arg(long)]
        kategori: Option<String>,
        /// En fazla kaç olay
        #[arg(long, default_value_t = 500)]
        adet: u32,
        /// CSV olarak yaz (dosyaya: kalkan gunluk --csv > gunluk.csv)
        #[arg(long)]
        csv: bool,
        #[arg(long, default_value = "/Library/Application Support/Kalkan/kalkan.sock")]
        soket: PathBuf,
    },
    /// Normal trafiğin ilk %70'iyle eğitir, kalanında yanlış alarmı ve saldırı pcap'lerinde yakalamayı ölçer
    Degerlendir {
        normal: PathBuf,
        #[arg(long)]
        tarama: Vec<PathBuf>,
        #[arg(long, default_value_t = 0.7)]
        oran: f64,
        #[arg(long, default_value_t = 99.5)]
        yuzdelik: f64,
    },
}

fn main() -> Result<()> {
    match Cli::parse().komut {
        Komut::Egit { pcapler, model, yuzdelik } => egit(&pcapler, &model, yuzdelik),
        Komut::Izle { pcap, model, db } => izle(&pcap, &model, &db),
        Komut::Uyarilar { db } => uyarilari_goster(&db),
        Komut::Durum { soket } => servis_durumu(&soket),
        Komut::Gunluk { saat, kategori, adet, csv, soket } => gunluk(&soket, saat, kategori, adet, csv),
        Komut::Tara { soket } => tara(&soket),
        Komut::Degerlendir { normal, tarama, oran, yuzdelik } => degerlendir(&normal, &tarama, oran, yuzdelik),
    }
}

/// Bir pcap'teki tüm akışların özellik kayıtları (kendi 60 sn penceresiyle).
fn kayitlar(yol: &Path) -> Result<Vec<AkisKaydi>> {
    let mut pencere = Pencere::new();
    let mut liste = Vec::new();
    let ozet = pcap_akislari(yol, |a| liste.push(pencere.kayit_olustur(&a))).map_err(anyhow::Error::msg)?;
    eprintln!("  {}: {} paket, {} akış ({} paket atlandı)", yol.display(), ozet.paket, liste.len(), ozet.atlanan);
    Ok(liste)
}

fn yerel_saat(us: u64) -> String {
    Local
        .timestamp_micros(us as i64)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .unwrap_or_default()
}

fn egit(pcapler: &[PathBuf], model: &Path, yuzdelik: f64) -> Result<()> {
    if pcapler.is_empty() {
        bail!("En az bir pcap dosyası ver: kalkan egit pcap/normal.pcap");
    }
    let t = Instant::now();
    let mut hepsi = Vec::new();
    for p in pcapler {
        hepsi.extend(kayitlar(p)?);
    }
    if hepsi.len() < 50 {
        bail!("Sadece {} akış var; en az birkaç yüz akış gerekli. Daha uzun yakalama yap.", hepsi.len());
    }
    let d = Dedektor::egit(&hepsi, yuzdelik);
    let alarm = hepsi.iter().filter(|k| d.skorla(k).anomali).count();
    d.kaydet(model).with_context(|| format!("{} yazılamadı", model.display()))?;
    println!(
        "Eğitildi: {} akış | orman eşiği {:.3} | sapma eşiği {:.1} | {:.1} sn",
        hepsi.len(), d.orman_esik, d.sapma_esik, t.elapsed().as_secs_f64()
    );
    println!("Eğitim trafiğinde alarm: {alarm} akış (%{:.1})", 100.0 * alarm as f64 / hepsi.len() as f64);
    println!("Kaydedildi: {}", model.display());
    Ok(())
}

fn db_ac(yol: &Path) -> Result<Connection> {
    let db = Connection::open(yol)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS akislar (
            zaman_us INTEGER, zaman TEXT, kaynak_ip TEXT, kaynak_port INTEGER,
            hedef_ip TEXT, hedef_port INTEGER, protokol TEXT, paket INTEGER, bayt INTEGER,
            sure_ms REAL, skor REAL, sapma REAL, risk REAL, anomali INTEGER, neden TEXT, kaynak TEXT);
         CREATE INDEX IF NOT EXISTS ix_zaman ON akislar(zaman_us);",
    )?;
    Ok(db)
}

fn izle(pcap: &Path, model: &Path, db_yolu: &Path) -> Result<()> {
    let d = Dedektor::yukle(model)
        .with_context(|| format!("Model yok ({}). Önce: kalkan egit pcap/normal.pcap", model.display()))?;
    let mut db = db_ac(db_yolu)?;
    let kaynak_adi = pcap.file_name().unwrap_or_default().to_string_lossy().to_string();
    let t = Instant::now();

    let tx = db.transaction()?;
    let (mut toplam, mut anomali) = (0usize, 0usize);
    // aynı kaynak + aynı tür için 60 sn'de bir satır yazdır
    let mut son_bildirim: std::collections::HashMap<(String, &str), (u64, usize)> = Default::default();
    {
        let mut ekle = tx.prepare(
            "INSERT INTO akislar VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        )?;
        let mut pencere = Pencere::new();
        let mut hata = None;
        pcap_akislari(pcap, |a| {
            let k = pencere.kayit_olustur(&a);
            let s = d.skorla(&k);
            toplam += 1;
            if s.anomali {
                anomali += 1;
                bildir(&k, &s, &mut son_bildirim);
            }
            if let Err(e) = kaydet(&mut ekle, &k, &s, &kaynak_adi) {
                hata.get_or_insert(e);
            }
        })
        .map_err(anyhow::Error::msg)?;
        if let Some(e) = hata {
            return Err(e.into());
        }
    }
    tx.commit()?;
    println!(
        "\nBitti: {toplam} akış, {anomali} anomali ({:.2} sn). Veritabanı: {}",
        t.elapsed().as_secs_f64(), db_yolu.display()
    );
    Ok(())
}

fn bildir(k: &AkisKaydi, s: &Sonuc, son: &mut std::collections::HashMap<(String, &'static str), (u64, usize)>) {
    let tur = tur_bul(&s.neden).0;
    let anahtar = (k.kaynak.to_string(), tur);
    match son.get_mut(&anahtar) {
        Some((zaman, bastirilan)) if k.ilk_us - *zaman < 60_000_000 => *bastirilan += 1,
        onceki => {
            let ek = match onceki {
                Some((_, n)) if *n > 0 => format!("  (+{n} benzer akış)"),
                _ => String::new(),
            };
            println!(
                "\x1b[91m⚠ {tur}: {} {}:{} → {}:{}  {}{ek}\x1b[0m",
                k.protokol_adi(), k.kaynak, k.kaynak_port, k.hedef, k.hedef_port, s.neden
            );
            son.insert(anahtar, (k.ilk_us, 0));
        }
    }
}

fn kaydet(ekle: &mut rusqlite::Statement, k: &AkisKaydi, s: &Sonuc, kaynak_adi: &str) -> rusqlite::Result<()> {
    ekle.execute(params![
        k.ilk_us as i64, yerel_saat(k.ilk_us), k.kaynak.to_string(), k.kaynak_port,
        k.hedef.to_string(), k.hedef_port, k.protokol_adi(), k.paket as i64, k.bayt as i64,
        k.sure_ms, s.skor, s.sapma, s.risk, s.anomali as i32, s.neden, kaynak_adi
    ])?;
    Ok(())
}

fn uyarilari_goster(db_yolu: &Path) -> Result<()> {
    let db = Connection::open(db_yolu)?;
    let mut sorgu = db.prepare(
        "SELECT zaman_us, kaynak_ip, hedef_ip, hedef_port, risk, sapma, neden FROM akislar WHERE anomali = 1",
    )?;
    let akislar = sorgu
        .query_map([], |r| {
            Ok(AnomaliAkisi {
                zaman_us: r.get::<_, i64>(0)? as u64,
                kaynak: r.get::<_, String>(1)?.parse().unwrap(),
                hedef: r.get::<_, String>(2)?.parse().unwrap(),
                hedef_port: r.get(3)?,
                risk: r.get(4)?,
                sapma: r.get(5)?,
                neden: r.get(6)?,
                surec: None,
                alan_adi: None,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let uyarilar = uyari::grupla(akislar);
    if uyarilar.is_empty() {
        println!("✅ Uyarı yok.");
    }
    for u in &uyarilar {
        let isaret = if u.risk >= 3.0 { "🔴" } else { "🟠" };
        let hedefler: Vec<String> = u.hedefler.iter().map(|h| h.to_string()).collect();
        println!("{isaret} {}  ·  {}  ·  risk {:.1}", u.tur, u.kaynak, u.risk);
        println!(
            "   {} · {} akış · {} hedef · {} port · hedefler: {}",
            yerel_saat(u.ilk_us), u.akis, u.hedef_sayisi, u.port_sayisi, hedefler.join(", ")
        );
        println!("   {}\n", u.ornek_neden);
    }
    Ok(())
}

fn gunluk(soket: &Path, saat: u64, kategori: Option<String>, adet: u32, csv: bool) -> Result<()> {
    let cevap = servise_sor(
        soket,
        serde_json::json!({"komut": "olaylar", "saat": saat, "kategori": kategori.unwrap_or_default(), "adet": adet}),
    )?;
    if let Some(hata) = cevap.get("hata") {
        anyhow::bail!("Servis: {hata}");
    }
    let mut olaylar = cevap.as_array().cloned().unwrap_or_default();
    olaylar.reverse(); // eskiden yeniye
    let zaman = |o: &serde_json::Value| {
        let us = o["zaman_us"].as_i64().unwrap_or(0);
        chrono::DateTime::from_timestamp_micros(us)
            .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default()
    };
    if csv {
        let alan = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        println!("zaman,kategori,seviye,mesaj,ayrinti");
        for o in &olaylar {
            println!(
                "{},{},{},{},{}",
                zaman(o),
                o["kategori"].as_str().unwrap_or(""),
                o["seviye"].as_str().unwrap_or(""),
                alan(o["mesaj"].as_str().unwrap_or("")),
                alan(&if o["ayrinti"].is_null() { String::new() } else { o["ayrinti"].to_string() }),
            );
        }
        return Ok(());
    }
    if olaylar.is_empty() {
        println!("Son {saat} saatte olay yok.");
    }
    for o in &olaylar {
        let simge = match o["seviye"].as_str() {
            Some("kritik") => "🔴",
            Some("uyari") => "🟠",
            _ => "⚪",
        };
        println!("{} {simge} [{:<6}] {}", zaman(o), o["kategori"].as_str().unwrap_or(""), o["mesaj"].as_str().unwrap_or(""));
    }
    Ok(())
}

fn tara(soket: &Path) -> Result<()> {
    servise_sor(soket, serde_json::json!({"komut": "tarama_baslat"}))?;
    println!("🔍 Ağ taranıyor (kendi yerel ağın)...");
    loop {
        std::thread::sleep(std::time::Duration::from_millis(600));
        let d = servise_sor(soket, serde_json::json!({"komut": "tarama_durum"}))?;
        let asama = d["asama"].as_str().unwrap_or("");
        print!("\r  {} · %{}      ", asama, d["ilerleme"].as_u64().unwrap_or(0));
        use std::io::Write;
        std::io::stdout().flush().ok();
        if !d["calisiyor"].as_bool().unwrap_or(false) {
            println!();
            if let Some(hata) = asama.strip_prefix("hata: ") {
                anyhow::bail!("{hata}");
            }
            let bos: Vec<serde_json::Value> = vec![];
            let cihazlar = d["cihazlar"].as_array().unwrap_or(&bos);
            println!("\n📋 {} ({} cihaz):", d["ag"].as_str().unwrap_or("-"), cihazlar.len());
            for c in cihazlar {
                let ad = c["ad"].as_str().or(c["uretici"].as_str()).unwrap_or("");
                let bu = if c["bu_mac"].as_bool().unwrap_or(false) { " (bu Mac)" } else { "" };
                let bos2: Vec<serde_json::Value> = vec![];
                let portlar = c["portlar"].as_array().unwrap_or(&bos2);
                println!("\n  ● {} {}{}", c["ip"].as_str().unwrap_or("?"), ad, bu);
                if portlar.is_empty() {
                    println!("      açık port yok");
                }
                for p in portlar {
                    let simge = match p["seviye"].as_str() { Some("yuksek") => "🔴", Some("orta") => "🟠", _ => "⚪" };
                    let surum = p["surum"].as_str().filter(|s| !s.is_empty()).map(|s| format!(" · {s}")).unwrap_or_default();
                    println!("      {simge} {:>5}  {}{surum}", p["port"].as_u64().unwrap_or(0), p["servis"].as_str().unwrap_or(""));
                    if let Some(o) = p["oneri"].as_str().filter(|o| !o.is_empty()) {
                        println!("             → {o}");
                    }
                    if let Some(n) = p["surum_notu"].as_str().filter(|n| !n.is_empty()) {
                        println!("             ⚠ {n}");
                    }
                    if let Some(cveler) = p["cveler"].as_array() {
                        for c in cveler {
                            let fidye = if c["fidye"].as_bool().unwrap_or(false) { " [fidye yazılımı]" } else { "" };
                            println!("             🛑 {}{fidye} — {} (aktif sömürülüyor, sürümünü doğrula)",
                                c["cve"].as_str().unwrap_or(""), c["baslik"].as_str().unwrap_or(""));
                        }
                    }
                }
            }
            return Ok(());
        }
    }
}

fn servise_sor(soket: &Path, istek: serde_json::Value) -> Result<serde_json::Value> {
    use std::io::{BufRead, BufReader, Write};
    let mut akim = std::os::unix::net::UnixStream::connect(soket).with_context(|| {
        format!("Servise bağlanılamadı ({}). Servis çalışıyor mu?", soket.display())
    })?;
    writeln!(akim, "{istek}")?;
    let mut satir = String::new();
    BufReader::new(akim).read_line(&mut satir)?;
    Ok(serde_json::from_str(&satir)?)
}

fn servis_durumu(soket: &Path) -> Result<()> {
    let d = servise_sor(soket, serde_json::json!({"komut": "durum"}))?;
    let u = |k: &str| d[k].as_u64().unwrap_or(0);
    println!("🛡️  Kalkan servisi · arayüz: {}", d["arayuz"].as_str().unwrap_or("-"));
    if d["mod_"] == "ogrenme" {
        // Başlangıç ilk akış kaydedilince yazılır; o zamana kadar ilerleme %0
        let gecen = match u("ogrenme_baslangic_us") {
            0 => 0,
            b => u("son_paket_us").saturating_sub(b),
        };
        let yuzde = (100 * gecen / u("ogrenme_sure_us").max(1)).min(100);
        println!(
            "   📚 Öğrenme modu: %{yuzde} · {} / en az {} normal akış toplandı",
            d["ogrenme_akis"], d["min_ogrenme_akis"]
        );
    } else {
        println!(
            "   👁️  İzleme modu · model {} akışla eğitildi ({})",
            d["egitim_akis"], yerel_saat(u("son_egitim_us"))
        );
    }
    println!("   {} akış işlendi · {} anomali · {} açık akış", u("toplam_akis"), u("anomali"), u("acik_akis"));

    let uyarilar = servise_sor(soket, serde_json::json!({"komut": "uyarilar", "saat": 24}))?;
    let liste = uyarilar.as_array().cloned().unwrap_or_default();
    println!("\nSon 24 saatin uyarıları: {}", liste.len());
    for x in liste.iter().take(10) {
        let risk = x["risk"].as_f64().unwrap_or(0.0);
        println!(
            "  {} {} · {} · risk {risk:.1} · {} akış · {}",
            if risk >= 3.0 { "🔴" } else { "🟠" },
            x["tur"].as_str().unwrap_or(""), x["kaynak"].as_str().unwrap_or(""),
            x["akis"], x["ornek_neden"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

fn degerlendir(normal: &Path, taramalar: &[PathBuf], oran: f64, yuzdelik: f64) -> Result<()> {
    let mut hepsi = kayitlar(normal)?;
    hepsi.sort_by_key(|k| k.ilk_us);
    let kes = (hepsi.len() as f64 * oran) as usize;
    let (egitim, test) = hepsi.split_at(kes);
    let d = Dedektor::egit(egitim, yuzdelik);
    let oran_hesapla = |k: &[AkisKaydi]| {
        let n = k.iter().filter(|x| d.skorla(x).anomali).count();
        (n, k.len(), 100.0 * n as f64 / k.len().max(1) as f64)
    };
    let (n, t, y) = oran_hesapla(egitim);
    println!("\nEşikler: orman {:.3} · sapma {:.1}", d.orman_esik, d.sapma_esik);
    println!("Eğitim kısmında alarm:          {n}/{t} (%{y:.1})");
    let (n, t, y) = oran_hesapla(test);
    println!("GÖRÜLMEMİŞ normal trafikte alarm: {n}/{t} (%{y:.1})   ← yanlış alarm oranı");
    for p in taramalar {
        let k = kayitlar(p)?;
        let (n, t, y) = oran_hesapla(&k);
        println!("{} yakalanan: {n}/{t} (%{y:.1})", p.display());
    }
    Ok(())
}
