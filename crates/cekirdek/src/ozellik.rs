//! Akıştan sayısal özellik çıkarma.
//!
//! Eğitimde ve izlemede aynı kod kullanılır; model her zaman aynı şekilde
//! hesaplanmış değerleri görür.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::akis::Akis;
use crate::paket;

pub const PENCERE_US: u64 = 60_000_000;

/// Isolation Forest'a giren özellikler (sıra önemli).
pub const OZELLIK_ADLARI: [&str; 25] = [
    "sure_log", "paket_log", "bayt_log",
    "giden_paket_log", "gelen_paket_log", "giden_bayt_log", "gelen_bayt_log",
    "gelen_giden_oran", "ort_paket_boyu", "std_paket_boyu", "ort_paket_arasi_log",
    "syn", "rst", "fin", "psh", "syn_orani",
    "tcp", "udp", "icmp", "iyi_bilinen_port", "yuksek_port",
    "kaynak_akis_60s_log", "kaynak_farkli_port_60s_log", "kaynak_farkli_hedef_60s_log",
    "kaynak_basarisiz_oran_60s",
];

/// Sapma kontrolü yapılan özellikler ve kullanıcıya gösterilen açıklamaları.
/// Sayımlar ham ölçekte: log 1000 portu da 7 portu da birbirine yakın gösterir.
/// SYN/RST tek akışta kontrol edilmiyor: VPN'deki SYN tekrarları yanlış alarm üretiyor.
pub const SAPMA_ADLARI: [(&str, &str); 11] = [
    ("sure_log", "akış süresi"),
    ("paket_log", "paket sayısı"),
    ("bayt_log", "toplam veri"),
    ("giden_bayt_log", "giden veri"),
    ("gelen_bayt_log", "gelen veri"),
    ("gelen_giden_oran", "gelen/giden veri dengesi"),
    ("ort_paket_boyu", "ortalama paket boyu"),
    ("kaynak_akis_60s", "kaynağın 60 sn'deki akış sayısı"),
    ("kaynak_farkli_port_60s", "kaynağın 60 sn'de dokunduğu farklı port sayısı"),
    ("kaynak_farkli_hedef_60s", "kaynağın 60 sn'de bağlandığı farklı hedef sayısı"),
    ("kaynak_basarisiz_60s", "kaynağın 60 sn'deki başarısız bağlantı sayısı"),
];

/// Ham sayım mı (açıklamada değer gösterilir) yoksa log/oran mı?
pub fn sapma_ham_sayim_mi(i: usize) -> bool {
    i >= 7
}

/// Tek bir akışın hem bilgi alanları hem model girdileri.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AkisKaydi {
    pub ilk_us: u64,
    pub kaynak: IpAddr,
    pub kaynak_port: u16,
    pub hedef: IpAddr,
    pub hedef_port: u16,
    pub protokol: u8,
    pub paket: u64,
    pub bayt: u64,
    pub sure_ms: f64,
    pub ozellik: [f64; 25],
    pub sapma_girdi: [f64; 11],
}

impl AkisKaydi {
    pub fn protokol_adi(&self) -> &'static str {
        match self.protokol {
            paket::TCP => "TCP",
            paket::UDP => "UDP",
            paket::ICMP => "ICMP",
            paket::ICMPV6 => "ICMPv6",
            _ => "Diğer",
        }
    }
}

/// Her kaynak IP için son 60 sn'deki akışlar.
///
/// Tek bir akış normal görünse bile (2 paketlik reddedilmiş bağlantı), aynı IP'nin
/// kısa sürede yüzlerce porta dokunması port taramasıdır. Bu bilgi akışın içinde yok.
#[derive(Default)]
pub struct Pencere {
    kayit: HashMap<IpAddr, VecDeque<(u64, IpAddr, u16, bool)>>,
}

impl Pencere {
    pub fn new() -> Self {
        Self::default()
    }

    /// Akışı pencereye ekler ve (akış, farklı port, farklı hedef, başarısız) sayılarını döndürür.
    fn ekle(&mut self, a: &Akis) -> (usize, usize, usize, usize) {
        let q = self.kayit.entry(a.kaynak).or_default();
        let basarisiz = a.rst > 0 || a.gelen_paket == 0;
        q.push_back((a.ilk_us, a.hedef, a.hedef_port, basarisiz));
        let sinir = a.ilk_us.saturating_sub(PENCERE_US);
        while q.front().is_some_and(|k| k.0 < sinir) {
            q.pop_front();
        }
        let portlar: HashSet<u16> = q.iter().map(|k| k.2).collect();
        let hedefler: HashSet<IpAddr> = q.iter().map(|k| k.1).collect();
        (q.len(), portlar.len(), hedefler.len(), q.iter().filter(|k| k.3).count())
    }

    /// Uzun süre izlemede belleği sınırla: 60 sn'den eski kaynakları sil.
    pub fn temizle(&mut self, simdi_us: u64) {
        let sinir = simdi_us.saturating_sub(PENCERE_US);
        self.kayit.retain(|_, q| q.back().is_some_and(|k| k.0 >= sinir));
    }

    pub fn kayit_olustur(&mut self, a: &Akis) -> AkisKaydi {
        let (n, port, hedef, basarisiz) = self.ekle(a);
        let ln = |x: f64| x.ln_1p();
        let paket = a.paket().max(1) as f64;
        let ozellik = [
            ln(a.sure_ms()),
            ln(a.paket() as f64),
            ln(a.bayt() as f64),
            ln(a.giden_paket as f64),
            ln(a.gelen_paket as f64),
            ln(a.giden_bayt as f64),
            ln(a.gelen_bayt as f64),
            ln(a.gelen_bayt as f64) - ln(a.giden_bayt as f64),
            a.ort_boy(),
            a.std_boy(),
            ln(a.ort_ara_ms().max(0.0)),
            a.syn as f64,
            a.rst as f64,
            a.fin as f64,
            a.psh as f64,
            a.syn as f64 / paket,
            (a.protokol == paket::TCP) as u8 as f64,
            (a.protokol == paket::UDP) as u8 as f64,
            matches!(a.protokol, paket::ICMP | paket::ICMPV6) as u8 as f64,
            (a.hedef_port > 0 && a.hedef_port < 1024) as u8 as f64,
            (a.hedef_port >= 49152) as u8 as f64,
            ln(n as f64),
            ln(port as f64),
            ln(hedef as f64),
            basarisiz as f64 / n as f64,
        ];
        let sapma_girdi = [
            ozellik[0], ozellik[1], ozellik[2], ozellik[5], ozellik[6], ozellik[7], ozellik[8],
            n as f64, port as f64, hedef as f64, basarisiz as f64,
        ];
        AkisKaydi {
            ilk_us: a.ilk_us,
            kaynak: a.kaynak,
            kaynak_port: a.kaynak_port,
            hedef: a.hedef,
            hedef_port: a.hedef_port,
            protokol: a.protokol,
            paket: a.paket(),
            bayt: a.bayt(),
            sure_ms: a.sure_ms(),
            ozellik,
            sapma_girdi,
        }
    }
}
