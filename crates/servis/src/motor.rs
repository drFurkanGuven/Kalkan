//! Servisin beyni: paketleri akışa çevirir, öğrenme / izleme moduna göre işler,
//! SQLite'a yazar, modeli eğitir ve haftalık günceller.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr};

use cekirdek::isim;
use cekirdek::paket::{self, Baglanti};
use cekirdek::uyari::tur_bul;
use cekirdek::{Akis, AkisKaydi, AkisTablosu, Dedektor, Pencere, Sonuc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

pub const MIN_OGRENME_AKIS: i64 = 300;
const HAFTA_US: u64 = 7 * 24 * 3600 * 1_000_000;
const SAAT_US: u64 = 3600 * 1_000_000;
const EGITIM_SAKLAMA_US: u64 = 14 * 24 * 3600 * 1_000_000;
/// Anomaliler 30 gün, normal akışlar 7 gün saklanır (disk ~100 MB'ı geçmesin)
const AKIS_SAKLAMA_US: u64 = 30 * 24 * 3600 * 1_000_000;
const NORMAL_AKIS_SAKLAMA_US: u64 = 7 * 24 * 3600 * 1_000_000;
/// Haftalık yeniden eğitim için tutulan en fazla örnek (fazlası rastgele seyreltilir)
const EN_FAZLA_EGITIM: i64 = 60_000;
const ESIK_YUZDELIGI: f64 = 99.5;

/// API'nin okuduğu canlı durum özeti.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Durum {
    /// "ogrenme" veya "izleme"
    pub mod_: String,
    pub arayuz: String,
    pub ogrenme_baslangic_us: u64,
    pub ogrenme_sure_us: u64,
    pub ogrenme_akis: i64,
    pub min_ogrenme_akis: i64,
    pub son_egitim_us: u64,
    pub egitim_akis: usize,
    pub toplam_akis: u64,
    pub anomali: u64,
    pub acik_akis: usize,
    pub son_paket_us: u64,
    pub baslangic_us: u64,
    /// pf ile engelleme kullanılabilir mi (servis root ise)
    pub engelleme: bool,
    /// Bu Mac'in adresleri: arayüz uyarıda engellenecek "karşı tarafı" seçerken kullanır
    pub yerel_ipler: Vec<String>,
    /// ARP izleme özeti (ağ geçidi ve MAC adresi)
    pub arp: crate::arp::ArpDurumu,
}

enum Mod {
    Ogrenme,
    Izleme(Box<Dedektor>),
}

pub struct Motor {
    db: Connection,
    model_yolu: PathBuf,
    tablo: AkisTablosu,
    pencere: Pencere,
    mod_: Mod,
    ogrenme_sure_us: u64,
    ogrenme_baslangic_us: u64,
    son_egitim_us: u64,
    son_bakim_us: u64,
    arp: crate::arp::ArpIzleyici,
    son_arp_us: u64,
    /// ağdaki cihazlar (API ile paylaşılır, 5 sn'de bir güncellenir)
    pub cihazlar: Arc<Mutex<Vec<crate::arp::Cihaz>>>,
    son_cihaz_us: u64,
    /// soket → uygulama (libproc)
    soketler: crate::surecler::SoketHaritasi,
    /// DNS cevaplarından: IP → (alan adı, görülme zamanı)
    dns: HashMap<IpAddr, (String, u64)>,
    /// TLS SNI: akış → sunucu adı
    sni: HashMap<DortluAnahtar, String>,
    /// birden çok pakete bölünmüş ClientHello parçaları
    sni_bekleyen: HashMap<DortluAnahtar, Vec<u8>>,
    yerel: HashSet<IpAddr>,
    son_bildirim: HashMap<(String, &'static str), (u64, usize)>,
    pub durum: Arc<Mutex<Durum>>,
    /// Kullanıcının "bu normal" dediği (kaynak IP, uyarı türü) çiftleri. API ile paylaşılır.
    pub izinler: Izinler,
}

/// Bir uyarı için izin anahtarı: (kaynak IP, uyarı türü).
pub type Izinler = Arc<Mutex<HashSet<(String, String)>>>;

pub fn izinleri_oku(db: &Connection) -> HashSet<(String, String)> {
    let Ok(mut s) = db.prepare("SELECT kaynak_ip, tur FROM izinler") else { return HashSet::new() };
    s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .map(|it| it.flatten().collect())
        .unwrap_or_default()
}

pub fn db_ac(yol: &Path) -> Result<Connection> {
    let db = Connection::open(yol)?;
    db.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS akislar (
            zaman_us INTEGER, kaynak_ip TEXT, kaynak_port INTEGER, hedef_ip TEXT, hedef_port INTEGER,
            protokol TEXT, paket INTEGER, bayt INTEGER, sure_ms REAL,
            skor REAL, sapma REAL, risk REAL, anomali INTEGER, neden TEXT, arayuz TEXT);
         CREATE INDEX IF NOT EXISTS ix_akis_zaman ON akislar(zaman_us);
         CREATE INDEX IF NOT EXISTS ix_akis_anomali ON akislar(anomali, zaman_us);
         CREATE TABLE IF NOT EXISTS egitim (zaman_us INTEGER, kayit TEXT);
         CREATE INDEX IF NOT EXISTS ix_egitim_zaman ON egitim(zaman_us);
         CREATE TABLE IF NOT EXISTS ayar (anahtar TEXT PRIMARY KEY, deger TEXT);
         CREATE TABLE IF NOT EXISTS izinler (
            kaynak_ip TEXT, tur TEXT, zaman_us INTEGER, PRIMARY KEY (kaynak_ip, tur));
         CREATE TABLE IF NOT EXISTS cihaz_bilinen (
            ag TEXT, mac TEXT, ilk_us INTEGER, PRIMARY KEY (ag, mac));
         CREATE TABLE IF NOT EXISTS port_bilinen (
            proto TEXT, port INTEGER, surec TEXT, ilk_us INTEGER, PRIMARY KEY (proto, port, surec));
         CREATE TABLE IF NOT EXISTS engeller (
            ip TEXT PRIMARY KEY, baslangic_us INTEGER, bitis_us INTEGER, neden TEXT);",
    )?;
    // Eski veritabanlarına yeni sütunlar (zaten varsa hata verir, yok sayılır)
    for sutun in ["surec TEXT", "alan_adi TEXT"] {
        let _ = db.execute(&format!("ALTER TABLE akislar ADD COLUMN {sutun}"), []);
    }
    Ok(db)
}

/// TCP akışının dört öğesi: (istemci, istemci portu, sunucu, sunucu portu)
type DortluAnahtar = (IpAddr, u16, IpAddr, u16);

fn ayar_oku(db: &Connection, anahtar: &str) -> Option<u64> {
    db.query_row("SELECT deger FROM ayar WHERE anahtar = ?1", [anahtar], |r| r.get::<_, String>(0))
        .optional()
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
}

fn ayar_yaz(db: &Connection, anahtar: &str, deger: u64) -> Result<()> {
    db.execute(
        "INSERT INTO ayar VALUES (?1, ?2) ON CONFLICT(anahtar) DO UPDATE SET deger = excluded.deger",
        params![anahtar, deger.to_string()],
    )?;
    Ok(())
}

impl Motor {
    pub fn new(veri_dizini: &Path, ogrenme_sure_us: u64, arp_gecit: Option<Ipv4Addr>) -> Result<Self> {
        std::fs::create_dir_all(veri_dizini)?;
        // Veritabanında alan adları (tarama geçmişi) var: veritabanı sadece sahibine açık.
        // Klasör 0711: içi listelenemez ama soket adıyla erişilebilir (uygulama verilere
        // soket üzerinden, yönetici grubuyla ulaşır).
        {
            use std::os::unix::fs::PermissionsExt;
            let izin = |yol: &Path, kip: u32| {
                let _ = std::fs::set_permissions(yol, std::fs::Permissions::from_mode(kip));
            };
            izin(veri_dizini, 0o711);
            let db_yolu = veri_dizini.join("kalkan.db");
            if !db_yolu.exists() {
                let _ = std::fs::File::create(&db_yolu);
            }
            for ek in ["", "-wal", "-shm"] {
                let yol = veri_dizini.join(format!("kalkan.db{ek}"));
                if yol.exists() {
                    izin(&yol, 0o600);
                }
            }
        }
        let db = db_ac(&veri_dizini.join("kalkan.db"))?;
        let model_yolu = veri_dizini.join("model.json");
        let (mod_, son_egitim_us) = match Dedektor::yukle(&model_yolu) {
            Ok(d) => {
                crate::gunluk::bilgi(
                    crate::gunluk::Kategori::Sistem,
                    &format!("Model yüklendi ({} akışla eğitilmiş). İzleme modu.", d.egitim_akis),
                    serde_json::json!({"egitim_akis": d.egitim_akis}),
                );
                (Mod::Izleme(Box::new(d)), ayar_oku(&db, "son_egitim_us").unwrap_or(0))
            }
            Err(_) => (Mod::Ogrenme, 0),
        };
        let ogrenme_baslangic_us = ayar_oku(&db, "ogrenme_baslangic_us").unwrap_or(0);
        let izinler = Arc::new(Mutex::new(izinleri_oku(&db)));
        let mut m = Motor {
            db,
            model_yolu,
            tablo: AkisTablosu::new(),
            pencere: Pencere::new(),
            mod_,
            ogrenme_sure_us,
            ogrenme_baslangic_us,
            son_egitim_us,
            son_bakim_us: 0,
            arp: crate::arp::ArpIzleyici::new(arp_gecit, &veri_dizini.join("oui.csv")),
            cihazlar: Arc::new(Mutex::new(Vec::new())),
            son_cihaz_us: 0,
            son_arp_us: 0,
            soketler: crate::surecler::SoketHaritasi::baslat(),
            dns: HashMap::new(),
            sni: HashMap::new(),
            sni_bekleyen: HashMap::new(),
            yerel: crate::engel::yerel_ipler().into_iter().collect(),
            son_bildirim: HashMap::new(),
            durum: Arc::new(Mutex::new(Durum { min_ogrenme_akis: MIN_OGRENME_AKIS, ..Default::default() })),
            izinler,
        };
        m.durumu_guncelle();
        Ok(m)
    }

    pub fn arayuz_ayarla(&mut self, ad: &str) {
        self.durum.lock().unwrap().arayuz = ad.to_string();
    }

    /// Bir paketi işler. Kapanan akışlar hemen değerlendirilir.
    pub fn paket(&mut self, baglanti: Baglanti, veri: &[u8], zaman_us: u64) {
        if matches!(baglanti, Baglanti::Ethernet)
            && let Some(a) = paket::arp_coz(veri)
        {
            for olay in self.arp.paket(&a, zaman_us) {
                self.olay_kaydet(olay);
            }
            return;
        }
        let Some(p) = paket::coz(baglanti, veri, zaman_us) else { return };
        // Bu Mac yeni bir TCP bağlantısı açıyor (SYN, ACK yok): soket kapanmadan uygulamayı yakala
        if p.protokol == paket::TCP && p.tcp_bayrak & 0x12 == paket::SYN && self.yerel.contains(&p.kaynak) {
            self.soketler.uyandir();
        }
        self.isim_gozle(&p);
        let mut biten = Vec::new();
        self.tablo.ekle(&p, &mut |a| biten.push(a));
        for a in biten {
            self.akis_isle(a);
        }
        let mut d = self.durum.lock().unwrap();
        d.son_paket_us = zaman_us;
        if d.baslangic_us == 0 {
            d.baslangic_us = zaman_us;
        }
    }

    /// Saniyede bir çağrılır: zamanı dolan akışları kapatır, öğrenmeyi bitirir, bakım yapar.
    pub fn tik(&mut self, simdi_us: u64) {
        let mut biten = Vec::new();
        self.tablo.zamani_dolanlari_ver(simdi_us, &mut |a| biten.push(a));
        for a in biten {
            self.akis_isle(a);
        }
        if simdi_us.saturating_sub(self.son_cihaz_us) >= 5_000_000 {
            self.son_cihaz_us = simdi_us;
            *self.cihazlar.lock().unwrap() = self.arp.cihazlar();
            self.yeni_cihazlari_kaydet();
        }
        if simdi_us.saturating_sub(self.son_arp_us) >= 30_000_000 {
            self.son_arp_us = simdi_us;
            self.arp.gecidi_yenile();
        }
        self.ogrenmeyi_kontrol_et(simdi_us);
        self.haftalik_guncelleme(simdi_us);
        if simdi_us.saturating_sub(self.son_bakim_us) >= SAAT_US {
            self.bakim(simdi_us);
        }
        self.durumu_guncelle();
    }

    /// Arayüz değişti veya program kapanıyor: açık akışların hepsini kapat.
    pub fn bosalt(&mut self) {
        let mut biten = Vec::new();
        self.tablo.hepsini_ver(&mut |a| biten.push(a));
        for a in biten {
            self.akis_isle(a);
        }
        *self.cihazlar.lock().unwrap() = self.arp.cihazlar();
        self.yeni_cihazlari_kaydet();
        self.durumu_guncelle();
    }

    /// DNS cevaplarından ve TLS ClientHello'dan alan adlarını topla (pasif).
    fn isim_gozle(&mut self, p: &paket::Paket) {
        if p.yuk.is_empty() {
            return;
        }
        if p.protokol == paket::UDP && p.kaynak_port == 53 {
            for (ip, ad) in isim::dns_cevabi(p.yuk) {
                self.dns.insert(ip, (ad, p.zaman_us));
            }
        } else if p.protokol == paket::UDP && p.kaynak_port == 5353 {
            for (ip, ad) in isim::mdns_adlari(p.yuk) {
                if let IpAddr::V4(v4) = ip {
                    self.arp.ad_ekle(v4, ad);
                }
            }
        } else if p.protokol == paket::TCP {
            let anahtar = (p.kaynak, p.kaynak_port, p.hedef, p.hedef_port);
            let veri = match self.sni_bekleyen.remove(&anahtar) {
                Some(mut onceki) => {
                    onceki.extend_from_slice(p.yuk);
                    onceki
                }
                None if p.yuk[0] == 22 => p.yuk.to_vec(),
                None => return,
            };
            match isim::tls_sni(&veri) {
                Ok(Some(ad)) => {
                    self.sni.insert(anahtar, ad);
                }
                Ok(None) => {}
                Err(_) if veri.len() < 16 * 1024 && self.sni_bekleyen.len() < 2000 => {
                    self.sni_bekleyen.insert(anahtar, veri);
                }
                Err(_) => {}
            }
        }
    }

    /// Akışın uygulaması ve alan adı: (uygulama, alan adı)
    fn akisi_adlandir(&mut self, k: &AkisKaydi) -> (Option<String>, Option<String>) {
        let ileri = (k.kaynak, k.kaynak_port, k.hedef, k.hedef_port);
        let geri = (k.hedef, k.hedef_port, k.kaynak, k.kaynak_port);
        self.sni_bekleyen.remove(&ileri);
        let sni = self.sni.remove(&ileri).or_else(|| self.sni.remove(&geri));
        let (yerel_port, uzak, uzak_port) = if self.yerel.contains(&k.kaynak) {
            (k.kaynak_port, k.hedef, k.hedef_port)
        } else if self.yerel.contains(&k.hedef) {
            (k.hedef_port, k.kaynak, k.kaynak_port)
        } else {
            return (None, sni);
        };
        let alan = sni.or_else(|| self.dns.get(&uzak).map(|(ad, _)| ad.clone()));
        let surec = if k.protokol == paket::TCP || k.protokol == paket::UDP {
            self.soketler.bul(k.protokol, yerel_port, uzak, uzak_port)
        } else {
            None
        };
        (surec, alan)
    }

    fn akis_isle(&mut self, a: Akis) {
        let k = self.pencere.kayit_olustur(&a);
        let adlar = self.akisi_adlandir(&k);
        let sonuc = match &self.mod_ {
            Mod::Ogrenme => {
                if self.ogrenme_baslangic_us == 0 {
                    self.ogrenme_baslangic_us = k.ilk_us;
                    let _ = ayar_yaz(&self.db, "ogrenme_baslangic_us", k.ilk_us);
                    crate::gunluk::bilgi(crate::gunluk::Kategori::Sistem, "Öğrenme modu başladı: normal trafik kaydediliyor.", serde_json::Value::Null);
                }
                self.egitime_ekle(&k);
                None
            }
            Mod::Izleme(d) => {
                let mut s = d.skorla(&k);
                if s.anomali && self.izinli_mi(&k, &s) {
                    // kullanıcı bu kaynağın bu davranışını normal saydı
                    s.anomali = false;
                    s.neden = format!("izinli · {}", s.neden);
                }
                if s.anomali {
                    self.bildir(&k, &s, &adlar);
                } else {
                    self.egitime_ekle(&k); // haftalık güncelleme için normal örnek
                }
                Some(s)
            }
        };
        if let Err(e) = self.akisi_kaydet(&k, sonuc.as_ref(), &adlar) {
            log(&format!("Veritabanı hatası: {e}"));
        }
        let mut d = self.durum.lock().unwrap();
        d.toplam_akis += 1;
        if sonuc.is_some_and(|s| s.anomali) {
            d.anomali += 1;
        }
    }

    /// Ağda ilk kez görülen cihazları ağ başına kaydet; ağın tabanı oluştuktan sonra
    /// gelen yeni cihazı günlüğe yaz. (Ağ ilk kez görüldüğünde 10 dk sessizce taban kurulur.)
    fn yeni_cihazlari_kaydet(&mut self) {
        let yeniler = self.arp.yeni_cihazlari_al();
        let Some(ag) = self.arp.ag_kimligi() else { return };
        if yeniler.is_empty() {
            return;
        }
        let simdi = simdi_saat_us();
        let ag_ilk: Option<i64> = self
            .db
            .query_row("SELECT MIN(ilk_us) FROM cihaz_bilinen WHERE ag = ?1", [&ag], |r| r.get(0))
            .ok()
            .flatten();
        let taban_hazir = ag_ilk.is_some_and(|t| simdi.saturating_sub(t as u64) >= 10 * 60 * 1_000_000);
        let liste = self.arp.cihazlar();
        for mac in yeniler {
            let mac_s = cekirdek::paket::mac_yazi(&mac);
            let eklendi = self
                .db
                .execute("INSERT OR IGNORE INTO cihaz_bilinen VALUES (?1, ?2, ?3)", params![ag, mac_s, simdi as i64])
                .unwrap_or(0);
            if eklendi == 0 || !taban_hazir {
                continue;
            }
            let c = liste.iter().find(|c| c.mac == mac_s);
            let ipler = c.map(|c| c.ipler.join(", ")).unwrap_or_default();
            let kim = c
                .and_then(|c| c.ad.clone().or(c.uretici.clone()))
                .or_else(|| c.filter(|c| c.rastgele_mac).map(|_| "gizli MAC'li cihaz".into()))
                .unwrap_or_else(|| "bilinmeyen cihaz".into());
            crate::gunluk::uyari(
                crate::gunluk::Kategori::Ag,
                &format!("Ağa yeni cihaz katıldı: {kim} · {ipler} · {mac_s}"),
                serde_json::json!({"mac": mac_s, "ipler": c.map(|c| c.ipler.clone()), "ad": c.and_then(|c| c.ad.clone()),
                                   "uretici": c.and_then(|c| c.uretici.clone()), "ag": ag}),
            );
        }
    }

    /// Kural tabanlı bir olayı (ARP) uyarı olarak kaydet. Öğrenme modunda da çalışır.
    fn olay_kaydet(&mut self, o: crate::arp::Olay) {
        let tur = tur_bul(&o.neden).0;
        if self.izinler.lock().unwrap().contains(&(o.kaynak.to_string(), tur.to_string())) {
            return;
        }
        crate::gunluk::kritik(
            crate::gunluk::Kategori::Uyari,
            &format!("⚠ {tur}: {}", o.neden),
            serde_json::json!({"tur": tur, "kaynak": o.kaynak.to_string(), "hedef": o.hedef.to_string(), "risk": o.risk}),
        );
        let arayuz = self.durum.lock().unwrap().arayuz.clone();
        let sonuc = self.db.execute(
            "INSERT INTO akislar (zaman_us,kaynak_ip,kaynak_port,hedef_ip,hedef_port,protokol,paket,bayt,sure_ms,skor,sapma,risk,anomali,neden,arayuz) VALUES (?1,?2,0,?3,0,'ARP',?4,0,0,NULL,NULL,?5,1,?6,?7)",
            params![o.zaman_us as i64, o.kaynak.to_string(), o.hedef.to_string(), o.paket as i64, o.risk, o.neden, arayuz],
        );
        if let Err(e) = sonuc {
            log(&format!("Veritabanı hatası: {e}"));
        }
        self.durum.lock().unwrap().anomali += 1;
    }

    fn izinli_mi(&self, k: &AkisKaydi, s: &Sonuc) -> bool {
        let tur = tur_bul(&s.neden).0;
        self.izinler.lock().unwrap().contains(&(k.kaynak.to_string(), tur.to_string()))
    }

    fn egitime_ekle(&self, k: &AkisKaydi) {
        if let Ok(json) = serde_json::to_string(k) {
            let _ = self.db.execute("INSERT INTO egitim VALUES (?1, ?2)", params![k.ilk_us as i64, json]);
        }
    }

    fn akisi_kaydet(
        &self,
        k: &AkisKaydi,
        s: Option<&Sonuc>,
        (surec, alan): &(Option<String>, Option<String>),
    ) -> rusqlite::Result<()> {
        let arayuz = self.durum.lock().unwrap().arayuz.clone();
        self.db.execute(
            "INSERT INTO akislar (zaman_us,kaynak_ip,kaynak_port,hedef_ip,hedef_port,protokol,paket,bayt,sure_ms,skor,sapma,risk,anomali,neden,arayuz,surec,alan_adi)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                k.ilk_us as i64, k.kaynak.to_string(), k.kaynak_port, k.hedef.to_string(), k.hedef_port,
                k.protokol_adi(), k.paket as i64, k.bayt as i64, k.sure_ms,
                s.map(|s| s.skor), s.map(|s| s.sapma), s.map(|s| s.risk),
                s.is_some_and(|s| s.anomali) as i32, s.map(|s| s.neden.clone()).unwrap_or_default(), arayuz,
                surec, alan
            ],
        )?;
        Ok(())
    }

    /// Aynı kaynak + aynı tür için logda 60 sn'de bir satır.
    fn bildir(&mut self, k: &AkisKaydi, s: &Sonuc, (surec, alan): &(Option<String>, Option<String>)) {
        let tur = tur_bul(&s.neden).0;
        let anahtar = (k.kaynak.to_string(), tur);
        match self.son_bildirim.get_mut(&anahtar) {
            Some((zaman, n)) if k.ilk_us.saturating_sub(*zaman) < 60_000_000 => *n += 1,
            onceki => {
                let ek = match onceki {
                    Some((_, n)) if *n > 0 => format!(" (+{n} benzer akış)"),
                    _ => String::new(),
                };
                let kim = match (surec, alan) {
                    (Some(u), Some(a)) => format!(" [{u} → {a}]"),
                    (Some(u), None) => format!(" [{u}]"),
                    (None, Some(a)) => format!(" [{a}]"),
                    _ => String::new(),
                };
                let seviye = if s.risk >= 10.0 {
                    crate::gunluk::Seviye::Kritik
                } else if s.risk >= 3.0 {
                    crate::gunluk::Seviye::Uyari
                } else {
                    crate::gunluk::Seviye::Bilgi
                };
                crate::gunluk::olay(
                    crate::gunluk::Kategori::Uyari,
                    seviye,
                    &format!(
                        "⚠ {tur}: {} {}:{} → {}:{}{kim} · {}{ek}",
                        k.protokol_adi(), k.kaynak, k.kaynak_port, k.hedef, k.hedef_port, s.neden
                    ),
                    serde_json::json!({
                        "tur": tur, "protokol": k.protokol_adi(),
                        "kaynak": k.kaynak.to_string(), "kaynak_port": k.kaynak_port,
                        "hedef": k.hedef.to_string(), "hedef_port": k.hedef_port,
                        "risk": s.risk, "neden": s.neden, "uygulama": surec, "alan_adi": alan,
                    }),
                );
                self.son_bildirim.insert(anahtar, (k.ilk_us, 0));
            }
        }
    }

    fn egitim_kayitlari(&self, baslangic_us: u64) -> Result<Vec<AkisKaydi>> {
        let mut sorgu = self.db.prepare("SELECT kayit FROM egitim WHERE zaman_us >= ?1")?;
        let liste = sorgu
            .query_map([baslangic_us as i64], |r| r.get::<_, String>(0))?
            .filter_map(|r| r.ok().and_then(|s| serde_json::from_str(&s).ok()))
            .collect();
        Ok(liste)
    }

    fn egit(&mut self, kayitlar: &[AkisKaydi], simdi_us: u64) -> Result<()> {
        let d = Dedektor::egit(kayitlar, ESIK_YUZDELIGI);
        d.kaydet(&self.model_yolu)?;
        crate::gunluk::bilgi(
            crate::gunluk::Kategori::Sistem,
            &format!(
                "Model eğitildi: {} akış · orman eşiği {:.3} · sapma eşiği {:.1}",
                kayitlar.len(), d.orman_esik, d.sapma_esik
            ),
            serde_json::json!({"akis": kayitlar.len(), "orman_esik": d.orman_esik, "sapma_esik": d.sapma_esik}),
        );
        self.mod_ = Mod::Izleme(Box::new(d));
        self.son_egitim_us = simdi_us;
        ayar_yaz(&self.db, "son_egitim_us", simdi_us)?;
        Ok(())
    }

    fn ogrenme_akis_sayisi(&self) -> i64 {
        self.db.query_row("SELECT COUNT(*) FROM egitim", [], |r| r.get(0)).unwrap_or(0)
    }

    fn ogrenmeyi_kontrol_et(&mut self, simdi_us: u64) {
        if !matches!(self.mod_, Mod::Ogrenme) || self.ogrenme_baslangic_us == 0 {
            return;
        }
        if simdi_us.saturating_sub(self.ogrenme_baslangic_us) < self.ogrenme_sure_us
            || self.ogrenme_akis_sayisi() < MIN_OGRENME_AKIS
        {
            return;
        }
        match self.egitim_kayitlari(0) {
            Ok(k) => {
                if let Err(e) = self.egit(&k, simdi_us) {
                    crate::gunluk::uyari(crate::gunluk::Kategori::Sistem, &format!("Eğitim başarısız: {e}"), serde_json::Value::Null);
                } else {
                    crate::gunluk::bilgi(crate::gunluk::Kategori::Sistem, "Öğrenme tamamlandı. İzleme modu başladı.", serde_json::Value::Null);
                }
            }
            Err(e) => log(&format!("Eğitim verisi okunamadı: {e}")),
        }
    }

    /// Model haftada bir son 7 günün normal trafiğiyle yeniden eğitilir.
    fn haftalik_guncelleme(&mut self, simdi_us: u64) {
        if !matches!(self.mod_, Mod::Izleme(_)) || self.son_egitim_us == 0 {
            return;
        }
        if simdi_us.saturating_sub(self.son_egitim_us) < HAFTA_US {
            return;
        }
        match self.egitim_kayitlari(simdi_us.saturating_sub(HAFTA_US)) {
            Ok(k) if k.len() as i64 >= MIN_OGRENME_AKIS => {
                if let Err(e) = self.egit(&k, simdi_us) {
                    crate::gunluk::uyari(crate::gunluk::Kategori::Sistem, &format!("Haftalık güncelleme başarısız: {e}"), serde_json::Value::Null);
                }
            }
            _ => self.son_egitim_us = simdi_us, // yeterli veri yok, bir hafta sonra tekrar dene
        }
    }

    fn bakim(&mut self, simdi_us: u64) {
        self.son_bakim_us = simdi_us;
        let yerel = crate::engel::yerel_ipler();
        self.durum.lock().unwrap().yerel_ipler = yerel.iter().map(|ip| ip.to_string()).collect();
        self.yerel = yerel.into_iter().collect();
        // ad önbellekleri sınırsız büyümesin
        self.dns.retain(|_, (_, t)| simdi_us.saturating_sub(*t) < 6 * SAAT_US);
        if self.sni.len() > 50_000 {
            self.sni.clear();
        }
        self.pencere.temizle(simdi_us);
        // öğrenme sırasında eğitim verisi silinmez
        if matches!(self.mod_, Mod::Izleme(_)) {
            let _ = self.db.execute(
                "DELETE FROM egitim WHERE zaman_us < ?1",
                [simdi_us.saturating_sub(EGITIM_SAKLAMA_US) as i64],
            );
        }
        let _ = self.db.execute(
            "DELETE FROM akislar WHERE zaman_us < ?1",
            [simdi_us.saturating_sub(AKIS_SAKLAMA_US) as i64],
        );
        crate::gunluk::temizle();
        let _ = self.db.execute(
            "DELETE FROM akislar WHERE anomali = 0 AND zaman_us < ?1",
            [simdi_us.saturating_sub(NORMAL_AKIS_SAKLAMA_US) as i64],
        );
        // İzleme modunda eğitim örneklerini sınırla: rastgele seyreltme, haftanın her
        // döneminden örnek kalsın. (Öğrenme modunda dokunulmaz.)
        if matches!(self.mod_, Mod::Izleme(_)) {
            let fazla = self.ogrenme_akis_sayisi() - EN_FAZLA_EGITIM;
            if fazla > 0 {
                let _ = self.db.execute(
                    "DELETE FROM egitim WHERE rowid IN (SELECT rowid FROM egitim ORDER BY random() LIMIT ?1)",
                    [fazla],
                );
            }
        }
    }

    fn durumu_guncelle(&mut self) {
        let ogrenme_akis = if matches!(self.mod_, Mod::Ogrenme) { self.ogrenme_akis_sayisi() } else { 0 };
        let egitim_akis = match &self.mod_ {
            Mod::Izleme(d) => d.egitim_akis,
            Mod::Ogrenme => 0,
        };
        let mut d = self.durum.lock().unwrap();
        d.mod_ = match self.mod_ {
            Mod::Ogrenme => "ogrenme".into(),
            Mod::Izleme(_) => "izleme".into(),
        };
        d.ogrenme_baslangic_us = self.ogrenme_baslangic_us;
        d.ogrenme_sure_us = self.ogrenme_sure_us;
        d.ogrenme_akis = ogrenme_akis;
        d.son_egitim_us = self.son_egitim_us;
        d.egitim_akis = egitim_akis;
        d.acik_akis = self.tablo.acik_sayisi();
        d.arp = self.arp.durum();
    }
}

fn simdi_saat_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64
}

pub fn log(mesaj: &str) {
    eprintln!("{} {mesaj}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
}
