//! macOS pf (paket filtresi) ile IP engelleme.
//!
//! Sistemin /etc/pf.conf dosyasına dokunulmaz: varsayılan yapılandırmadaki
//! `anchor "com.apple/*"` noktasının altına kendi bölümümüzü (com.apple/kalkan)
//! yükleriz. Engellenen adresler bir pf tablosunda tutulur; ekleme/çıkarma
//! kuralları yeniden yüklemeden anında etki eder.
//!
//! pf'i `pfctl -E` ile referans sayarak açarız ve kapanışta `pfctl -X <jeton>`
//! ile bırakırız; böylece pf'i kullanan başka programları (VPN vb.) bozmayız.
//! Servis kapanınca bütün engeller kalkar, açılınca veritabanından geri yüklenir.
//!
//! Gizli mod: yerel ağ kartında (Wi-Fi / Ethernet) bu Mac'in başlatmadığı her gelen
//! paket sessizce düşürülür (ping, port taraması, servis keşfi). Kendi bağlantılarının
//! cevapları pf durum tablosu sayesinde geçer. ARP pf'in altında kaldığı için cihaz
//! ağda "var" görünür ama hiçbir şeye cevap vermez.

use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use rusqlite::{Connection, params};

use crate::gunluk::{self, Kategori};
use crate::motor::log;

const PFCTL: &str = "/sbin/pfctl";
const BOLUM: &str = "com.apple/kalkan";
const GIZLI_BOLUM: &str = "com.apple/kalkan_gizli";
const TABLO: &str = "kalkan_engel";
const KURALLAR: &str = "table <kalkan_engel> persist\n\
                        block drop quick from <kalkan_engel> to any\n\
                        block drop quick from any to <kalkan_engel>\n";

fn simdi_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

fn pfctl(argumanlar: &[&str], girdi: Option<&str>) -> Result<String> {
    let mut komut = Command::new(PFCTL)
        .args(argumanlar)
        .stdin(if girdi.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(metin) = girdi {
        komut.stdin.take().unwrap().write_all(metin.as_bytes())?;
    }
    let cikti = komut.wait_with_output()?;
    // pfctl bilgi mesajlarını da stderr'e yazar
    let metin = format!("{}{}", String::from_utf8_lossy(&cikti.stdout), String::from_utf8_lossy(&cikti.stderr));
    if !cikti.status.success() {
        bail!("pfctl {}: {}", argumanlar.join(" "), metin.trim());
    }
    Ok(metin)
}

/// Bu Mac'in kendi adresleri (bunlar asla engellenmez).
pub fn yerel_ipler() -> Vec<IpAddr> {
    let Ok(cikti) = Command::new("/sbin/ifconfig").output() else { return vec![] };
    String::from_utf8_lossy(&cikti.stdout)
        .lines()
        .filter_map(|satir| {
            let mut p = satir.split_whitespace();
            match p.next() {
                Some("inet") | Some("inet6") => p.next()?.split('%').next()?.parse().ok(),
                _ => None,
            }
        })
        .collect()
}

/// Engellenirse internet bağlantısını kesecek adresler: ağ geçitleri ve VPN sunucusu.
fn kritik_adresler() -> HashSet<IpAddr> {
    let mut adresler = HashSet::new();
    for aile in [&["-n", "get", "default"][..], &["-n", "get", "-inet6", "default"][..]] {
        if let Ok(c) = Command::new("/sbin/route").args(aile).output() {
            for satir in String::from_utf8_lossy(&c.stdout).lines() {
                if let Some(g) = satir.trim().strip_prefix("gateway:")
                    && let Ok(ip) = g.trim().split('%').next().unwrap_or("").parse() {
                        adresler.insert(ip);
                    }
            }
        }
    }
    // Ağ geçidi üzerinden giden tek-adres rotaları: genelde VPN sunucusunun kendisi
    if let Ok(c) = Command::new("/usr/sbin/netstat").args(["-rn", "-f", "inet"]).output() {
        for satir in String::from_utf8_lossy(&c.stdout).lines() {
            let p: Vec<&str> = satir.split_whitespace().collect();
            if p.len() >= 3 && p[2].contains('H') && p[2].contains('G')
                && let (Ok(hedef), Ok(_)) = (p[0].parse::<IpAddr>(), p[1].parse::<IpAddr>()) {
                    adresler.insert(hedef);
                }
        }
    }
    adresler
}

/// Engellemeye izin verilmeyen adres mi? Neden döndürür.
pub fn korumali(ip: IpAddr) -> Option<&'static str> {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return Some("özel adres");
    }
    if let IpAddr::V4(v4) = ip
        && (v4.is_broadcast() || v4.is_link_local()) {
            return Some("özel adres");
        }
    if let IpAddr::V6(v6) = ip
        && (v6.segments()[0] & 0xffc0) == 0xfe80 {
            return Some("özel adres");
        }
    if yerel_ipler().contains(&ip) {
        return Some("bu Mac'in kendi adresi");
    }
    if kritik_adresler().contains(&ip) {
        return Some("ağ geçidi veya VPN sunucusu; engellenirse internet kesilir");
    }
    None
}

fn gizli_kurallari(arayuz: &str, bonjour: bool) -> String {
    let mut k = format!(
        "# Kalkan gizli mod: {arayuz}\n\
         pass out quick on {arayuz} all flags any keep state\n\
         pass in quick on {arayuz} inet proto udp from any port 67 to any port 68\n\
         pass in quick on {arayuz} inet6 proto udp from any port 547 to any port 546\n\
         pass in quick on {arayuz} inet6 proto icmp6 icmp6-type {{ routersol, routeradv, neighbrsol, neighbradv, redir }}\n"
    );
    if bonjour {
        k += &format!("pass in quick on {arayuz} proto udp from any to any port 5353\n");
    }
    k += &format!("block drop in quick on {arayuz} all\n");
    k
}

#[derive(Default)]
struct Gizli {
    acik: bool,
    bonjour: bool,
    /// kuralların şu an yüklü olduğu arayüz
    arayuz: Option<String>,
}

pub struct Engelleyici {
    gizli: Mutex<Gizli>,
    db_yolu: PathBuf,
    /// pf açıldıysa bırakma jetonu; açılamadıysa nedeni
    durum: Result<String, String>,
    kilit: Mutex<()>,
}

impl Engelleyici {
    /// Kuralları yükler, pf'i açar, kayıtlı engelleri geri yükler, süre dolumu için iş parçacığı başlatır.
    pub fn baslat(db_yolu: &Path) -> Arc<Self> {
        let durum = (|| -> Result<String> {
            pfctl(&["-a", BOLUM, "-f", "-"], Some(KURALLAR))?;
            let cikti = pfctl(&["-E"], None)?;
            let jeton = cikti
                .lines()
                .find_map(|s| s.strip_prefix("Token : "))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            Ok(jeton)
        })()
        .map_err(|e| {
            let e = e.to_string();
            if e.contains("Permission denied") || e.contains("Operation not permitted") {
                "engelleme için servisin yönetici (root) olarak çalışması gerekiyor".to_string()
            } else {
                e
            }
        });

        let e = Arc::new(Engelleyici {
            gizli: Mutex::new(Gizli::default()),
            db_yolu: db_yolu.to_path_buf(),
            durum,
            kilit: Mutex::new(()),
        });
        match &e.durum {
            Ok(_) => {
                let n = e.geri_yukle().unwrap_or_else(|hata| {
                    gunluk::uyari(Kategori::Sistem, &format!("Engeller geri yüklenemedi: {hata}"), serde_json::Value::Null);
                    0
                });
                gunluk::bilgi(
                    Kategori::Kural,
                    &format!("Engelleme hazır (pf · {BOLUM}) · {n} etkin engel"),
                    serde_json::json!({"etkin_engel": n}),
                );
                if let Ok(c) = e.db() {
                    let oku = |a: &str| {
                        c.query_row("SELECT deger FROM ayar WHERE anahtar = ?1", [a], |r| r.get::<_, String>(0))
                            .map(|d| d == "1")
                            .unwrap_or(false)
                    };
                    let mut g = e.gizli.lock().unwrap();
                    g.acik = oku("gizli_mod");
                    g.bonjour = oku("gizli_bonjour");
                }
                e.gizli_uygula();
                let e2 = e.clone();
                std::thread::spawn(move || {
                    loop {
                        std::thread::sleep(Duration::from_secs(15));
                        if let Err(hata) = e2.suresi_dolanlari_kaldir() {
                            log(&format!("Engel süre kontrolü: {hata}"));
                        }
                        // Wi-Fi ↔ Ethernet değişirse gizli mod kurallarını yeni karta taşı
                        e2.gizli_uygula();
                    }
                });
            }
            Err(neden) => gunluk::uyari(
                Kategori::Sistem,
                &format!("Engelleme kapalı: {neden}"),
                serde_json::json!({"neden": neden}),
            ),
        }
        e
    }

    pub fn etkin(&self) -> bool {
        self.durum.is_ok()
    }

    fn hazir(&self) -> Result<()> {
        self.durum.as_ref().map(|_| ()).map_err(|n| anyhow!("Engelleme kullanılamıyor: {n}"))
    }

    fn db(&self) -> Result<Connection> {
        let c = Connection::open(&self.db_yolu)?;
        c.busy_timeout(Duration::from_secs(5))?;
        Ok(c)
    }

    fn geri_yukle(&self) -> Result<usize> {
        let c = self.db()?;
        c.execute("DELETE FROM engeller WHERE bitis_us > 0 AND bitis_us <= ?1", [simdi_us() as i64])?;
        let ipler: Vec<String> = c
            .prepare("SELECT ip FROM engeller")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        pfctl(&["-a", BOLUM, "-t", TABLO, "-T", "flush"], None)?;
        if !ipler.is_empty() {
            let mut arg = vec!["-a", BOLUM, "-t", TABLO, "-T", "add"];
            arg.extend(ipler.iter().map(String::as_str));
            pfctl(&arg, None)?;
        }
        Ok(ipler.len())
    }

    /// IP'yi engeller. `sure_dk` 0 ise kalıcı.
    pub fn engelle(&self, ip: IpAddr, sure_dk: u64, neden: &str) -> Result<()> {
        if let Some(sebep) = korumali(ip) {
            bail!("{ip} engellenemez: {sebep}");
        }
        self.hazir()?;
        let _k = self.kilit.lock().unwrap();
        let ip_s = ip.to_string();
        pfctl(&["-a", BOLUM, "-t", TABLO, "-T", "add", &ip_s], None)?;
        // Açık bağlantılar pf durum tablosunda yaşamaya devam eder; onları da kes
        let hepsi = if ip.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
        let _ = pfctl(&["-k", &ip_s], None);
        let _ = pfctl(&["-k", hepsi, "-k", &ip_s], None);
        let simdi = simdi_us();
        let bitis = if sure_dk == 0 { 0 } else { simdi + sure_dk * 60 * 1_000_000 };
        self.db()?.execute(
            "INSERT OR REPLACE INTO engeller VALUES (?1, ?2, ?3, ?4)",
            params![ip_s, simdi as i64, bitis as i64, neden],
        )?;
        let sure = if sure_dk == 0 { "kalıcı".to_string() } else { format!("{sure_dk} dk") };
        gunluk::uyari(
            Kategori::Kural,
            &format!("⛔ Engellendi: {ip} ({sure}) · {neden}"),
            serde_json::json!({"islem": "engelle", "ip": ip_s, "sure_dk": sure_dk, "bitis_us": bitis, "neden": neden}),
        );
        Ok(())
    }

    /// Engeli kaldırır. `sebep`: "kullanıcı" veya "süresi doldu" (günlük için).
    pub fn kaldir(&self, ip: IpAddr, sebep: &str) -> Result<()> {
        self.hazir()?;
        let _k = self.kilit.lock().unwrap();
        let ip_s = ip.to_string();
        pfctl(&["-a", BOLUM, "-t", TABLO, "-T", "delete", &ip_s], None)?;
        self.db()?.execute("DELETE FROM engeller WHERE ip = ?1", [&ip_s])?;
        gunluk::bilgi(
            Kategori::Kural,
            &format!("Engel kaldırıldı: {ip} ({sebep})"),
            serde_json::json!({"islem": "engel_kaldir", "ip": ip_s, "sebep": sebep}),
        );
        Ok(())
    }

    fn suresi_dolanlari_kaldir(&self) -> Result<()> {
        let dolanlar: Vec<String> = self
            .db()?
            .prepare("SELECT ip FROM engeller WHERE bitis_us > 0 AND bitis_us <= ?1")?
            .query_map([simdi_us() as i64], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for ip in dolanlar {
            if let Ok(ip) = ip.parse() {
                self.kaldir(ip, "süresi doldu")?;
            }
        }
        Ok(())
    }

    /// Gizli modu aç/kapat; ayar veritabanında saklanır, açılışta geri yüklenir.
    pub fn gizli_ayarla(&self, acik: bool, bonjour: bool) -> Result<()> {
        self.hazir()?;
        if acik && crate::yakalama::yerel_ag_arayuzu().is_none() {
            bail!("Wi-Fi veya Ethernet bağlantısı bulunamadı");
        }
        {
            let mut g = self.gizli.lock().unwrap();
            g.acik = acik;
            g.bonjour = bonjour;
            g.arayuz = None; // yeniden yüklensin
        }
        let c = self.db()?;
        for (anahtar, deger) in [("gizli_mod", acik), ("gizli_bonjour", bonjour)] {
            c.execute(
                "INSERT INTO ayar VALUES (?1, ?2) ON CONFLICT(anahtar) DO UPDATE SET deger = excluded.deger",
                params![anahtar, if deger { "1" } else { "0" }],
            )?;
        }
        self.gizli_uygula();
        Ok(())
    }

    /// İstenen gizli mod durumunu pf'e yansıtır (gerekirse).
    fn gizli_uygula(&self) {
        if self.durum.is_err() {
            return;
        }
        let mut g = self.gizli.lock().unwrap();
        let hedef = if g.acik { crate::yakalama::yerel_ag_arayuzu().map(|(a, _)| a) } else { None };
        if hedef == g.arayuz {
            return;
        }
        let sonuc = match &hedef {
            Some(a) => pfctl(&["-a", GIZLI_BOLUM, "-f", "-"], Some(&gizli_kurallari(a, g.bonjour))),
            None => pfctl(&["-a", GIZLI_BOLUM, "-F", "rules"], None),
        };
        match sonuc {
            Ok(_) => {
                match &hedef {
                    Some(a) => gunluk::bilgi(
                        Kategori::Kural,
                        &format!(
                            "🥷 Gizli mod açık: {a} üzerinde istenmeyen gelen trafik düşürülüyor{}",
                            if g.bonjour { " (Bonjour izinli)" } else { "" }
                        ),
                        serde_json::json!({"islem": "gizli_mod", "acik": true, "arayuz": a, "bonjour": g.bonjour}),
                    ),
                    None if g.arayuz.is_some() => gunluk::bilgi(
                        Kategori::Kural,
                        "Gizli mod kapatıldı.",
                        serde_json::json!({"islem": "gizli_mod", "acik": false}),
                    ),
                    None => {}
                }
                g.arayuz = hedef;
            }
            Err(e) => gunluk::uyari(Kategori::Kural, &format!("Gizli mod uygulanamadı: {e}"), serde_json::Value::Null),
        }
    }

    /// Panel için: gizli mod durumu ve düşürülen paket sayısı.
    pub fn gizli_durumu(&self) -> serde_json::Value {
        let g = self.gizli.lock().unwrap();
        let mut dusurulen = 0u64;
        if g.arayuz.is_some()
            && let Ok(cikti) = pfctl(&["-a", GIZLI_BOLUM, "-v", "-s", "rules"], None)
        {
            // "block drop in quick ..." satırından sonraki "[ ... Packets: N ...]" sayacı
            let mut blok = false;
            for satir in cikti.lines() {
                if satir.starts_with("block") {
                    blok = true;
                } else if blok && let Some(p) = satir.split("Packets:").nth(1) {
                    dusurulen = p.split_whitespace().next().and_then(|n| n.parse().ok()).unwrap_or(0);
                    break;
                }
            }
        }
        serde_json::json!({
            "acik": g.acik, "bonjour": g.bonjour, "arayuz": g.arayuz, "dusurulen": dusurulen,
        })
    }

    /// Servis kapanırken: kuralları boşalt, pf referansını bırak.
    pub fn kapat(&self) {
        if let Ok(jeton) = &self.durum {
            let _ = pfctl(&["-a", BOLUM, "-F", "all"], None);
            let _ = pfctl(&["-a", GIZLI_BOLUM, "-F", "all"], None);
            if !jeton.is_empty() {
                let _ = pfctl(&["-X", jeton], None);
            }
            log("Engeller kaldırıldı (servis kapanıyor).");
        }
    }
}
