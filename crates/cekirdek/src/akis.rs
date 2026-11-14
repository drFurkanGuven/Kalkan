//! Paketleri çift yönlü akışlara (flow) birleştirir.
//!
//! Aynı 5-tuple'a (iki uç IP, iki port, protokol) sahip paketler, yönü ne olursa
//! olsun tek akıştır. İlk paketi gönderen taraf "kaynak" sayılır. Akış 15 sn
//! sessiz kalırsa veya 120 sn'yi doldurursa kapanır ve dışarı verilir.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::paket::{self, Paket};

pub const BOSTA_ZAMAN_ASIMI_US: u64 = 15_000_000;
pub const AKTIF_ZAMAN_ASIMI_US: u64 = 120_000_000;
const TARAMA_ARALIGI_US: u64 = 1_000_000;

/// Yönden bağımsız akış anahtarı: küçük uç önce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Anahtar {
    a: (IpAddr, u16),
    b: (IpAddr, u16),
    protokol: u8,
}

impl Anahtar {
    fn yeni(p: &Paket) -> Self {
        let x = (p.kaynak, p.kaynak_port);
        let y = (p.hedef, p.hedef_port);
        let (a, b) = if x <= y { (x, y) } else { (y, x) };
        Anahtar { a, b, protokol: p.protokol }
    }
}

/// Kapanmış bir akışın tüm sayaçları.
#[derive(Clone, Debug)]
pub struct Akis {
    pub kaynak: IpAddr,
    pub hedef: IpAddr,
    pub kaynak_port: u16,
    pub hedef_port: u16,
    pub protokol: u8,
    pub ilk_us: u64,
    pub son_us: u64,
    pub giden_paket: u64,
    pub gelen_paket: u64,
    pub giden_bayt: u64,
    pub gelen_bayt: u64,
    pub syn: u64,
    pub rst: u64,
    pub fin: u64,
    pub psh: u64,
    boy_toplam: f64,
    boy_kare_toplam: f64,
    onceki_us: u64,
    ara_toplam_us: f64,
}

impl Akis {
    fn yeni(p: &Paket) -> Self {
        let mut a = Akis {
            kaynak: p.kaynak,
            hedef: p.hedef,
            kaynak_port: p.kaynak_port,
            hedef_port: p.hedef_port,
            protokol: p.protokol,
            ilk_us: p.zaman_us,
            son_us: p.zaman_us,
            giden_paket: 0,
            gelen_paket: 0,
            giden_bayt: 0,
            gelen_bayt: 0,
            syn: 0,
            rst: 0,
            fin: 0,
            psh: 0,
            boy_toplam: 0.0,
            boy_kare_toplam: 0.0,
            onceki_us: p.zaman_us,
            ara_toplam_us: 0.0,
        };
        a.ekle(p);
        a
    }

    fn ekle(&mut self, p: &Paket) {
        let giden = p.kaynak == self.kaynak && p.kaynak_port == self.kaynak_port;
        if giden {
            self.giden_paket += 1;
            self.giden_bayt += p.ip_boyu as u64;
        } else {
            self.gelen_paket += 1;
            self.gelen_bayt += p.ip_boyu as u64;
        }
        if self.paket() > 1 {
            self.ara_toplam_us += p.zaman_us.saturating_sub(self.onceki_us) as f64;
        }
        self.onceki_us = p.zaman_us;
        self.son_us = self.son_us.max(p.zaman_us);
        let boy = p.ip_boyu as f64;
        self.boy_toplam += boy;
        self.boy_kare_toplam += boy * boy;
        if p.protokol == paket::TCP {
            let f = p.tcp_bayrak;
            self.syn += (f & paket::SYN != 0) as u64;
            self.rst += (f & paket::RST != 0) as u64;
            self.fin += (f & paket::FIN != 0) as u64;
            self.psh += (f & paket::PSH != 0) as u64;
        }
    }

    pub fn paket(&self) -> u64 {
        self.giden_paket + self.gelen_paket
    }
    pub fn bayt(&self) -> u64 {
        self.giden_bayt + self.gelen_bayt
    }
    pub fn sure_ms(&self) -> f64 {
        (self.son_us - self.ilk_us) as f64 / 1000.0
    }
    pub fn ort_boy(&self) -> f64 {
        self.boy_toplam / self.paket().max(1) as f64
    }
    pub fn std_boy(&self) -> f64 {
        let n = self.paket().max(1) as f64;
        let ort = self.boy_toplam / n;
        (self.boy_kare_toplam / n - ort * ort).max(0.0).sqrt()
    }
    /// Paketler arası ortalama süre (ms)
    pub fn ort_ara_ms(&self) -> f64 {
        let n = self.paket();
        if n < 2 { 0.0 } else { self.ara_toplam_us / (n - 1) as f64 / 1000.0 }
    }
}

/// Açık akışları tutar, zamanı dolanları dışarı verir.
#[derive(Default)]
pub struct AkisTablosu {
    acik: HashMap<Anahtar, Akis>,
    son_tarama_us: u64,
}

impl AkisTablosu {
    pub fn new() -> Self {
        Self::default()
    }

    /// Paketi ilgili akışa ekler. Kapanan akışları `cikis`a verir.
    pub fn ekle(&mut self, p: &Paket, cikis: &mut impl FnMut(Akis)) {
        let anahtar = Anahtar::yeni(p);
        if let Some(a) = self.acik.get_mut(&anahtar) {
            let bosta = p.zaman_us.saturating_sub(a.son_us) > BOSTA_ZAMAN_ASIMI_US;
            let dolu = p.zaman_us.saturating_sub(a.ilk_us) > AKTIF_ZAMAN_ASIMI_US;
            if bosta || dolu {
                let eski = self.acik.remove(&anahtar).unwrap();
                cikis(eski);
                self.acik.insert(anahtar, Akis::yeni(p));
            } else {
                a.ekle(p);
            }
        } else {
            self.acik.insert(anahtar, Akis::yeni(p));
        }

        if p.zaman_us.saturating_sub(self.son_tarama_us) >= TARAMA_ARALIGI_US {
            self.zamani_dolanlari_ver(p.zaman_us, cikis);
            self.son_tarama_us = p.zaman_us;
        }
    }

    /// `simdi_us` anına göre süresi dolan akışları kapatır.
    pub fn zamani_dolanlari_ver(&mut self, simdi_us: u64, cikis: &mut impl FnMut(Akis)) {
        let mut biten: Vec<Anahtar> = self
            .acik
            .iter()
            .filter(|(_, a)| {
                simdi_us.saturating_sub(a.son_us) > BOSTA_ZAMAN_ASIMI_US
                    || simdi_us.saturating_sub(a.ilk_us) > AKTIF_ZAMAN_ASIMI_US
            })
            .map(|(k, _)| *k)
            .collect();
        biten.sort_by_key(|k| self.acik[k].ilk_us);
        for k in biten {
            cikis(self.acik.remove(&k).unwrap());
        }
    }

    /// Kalan tüm akışları kapatır (dosya sonu veya program kapanışı).
    pub fn hepsini_ver(&mut self, cikis: &mut impl FnMut(Akis)) {
        let mut hepsi: Vec<Akis> = self.acik.drain().map(|(_, a)| a).collect();
        hepsi.sort_by_key(|a| a.ilk_us);
        hepsi.into_iter().for_each(cikis);
    }

    pub fn acik_sayisi(&self) -> usize {
        self.acik.len()
    }
}
