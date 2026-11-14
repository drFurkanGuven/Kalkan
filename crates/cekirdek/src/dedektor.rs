//! Anomali dedektörü: Isolation Forest + özellik sapma kontrolü.
//!
//! Isolation Forest akışın genel "şeklinin" alışılmadık olup olmadığına bakar,
//! ama 25 özellikten sadece birkaçı aşırı uçtaysa (port taraması: "60 sn'de
//! 1000 farklı port") bunu kaçırır. Sapma kontrolü her özelliği normal
//! trafikteki aralığıyla tek tek karşılaştırır ve alarmın nedenini söyler.

use serde::{Deserialize, Serialize};

use crate::orman::IsolationForest;
use crate::ozellik::{AkisKaydi, SAPMA_ADLARI, sapma_ham_sayim_mi};

const AGAC_SAYISI: usize = 200;
const TOHUM: u64 = 42;
const MIN_OLCEK: f64 = 1.0;
const MIN_Z_ESIK: f64 = 6.0;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dedektor {
    orman: IsolationForest,
    pub orman_esik: f64,
    medyan: Vec<f64>,
    olcek: Vec<f64>,
    pub sapma_esik: f64,
    pub egitim_akis: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sonuc {
    pub skor: f64,
    pub sapma: f64,
    pub anomali: bool,
    pub neden: String,
    /// İki kontrolün ortak ölçeği: 1'in üstü = anomali
    pub risk: f64,
}

/// numpy/pandas ile aynı: sıralı dizide doğrusal ara değerli yüzdelik.
pub fn yuzdelik(degerler: &[f64], p: f64) -> f64 {
    let mut s: Vec<f64> = degerler.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    if s.is_empty() {
        return 0.0;
    }
    let konum = (p / 100.0) * (s.len() - 1) as f64;
    let (alt, ust) = (konum.floor() as usize, konum.ceil() as usize);
    s[alt] + (s[ust] - s[alt]) * (konum - alt as f64)
}

impl Dedektor {
    pub fn egit(kayitlar: &[AkisKaydi], esik_yuzdeligi: f64) -> Self {
        let veri: Vec<Vec<f64>> = kayitlar.iter().map(|k| k.ozellik.to_vec()).collect();
        let orman = IsolationForest::egit(&veri, AGAC_SAYISI, TOHUM);
        let skorlar: Vec<f64> = veri.iter().map(|x| orman.skor(x)).collect();
        let orman_esik = yuzdelik(&skorlar, esik_yuzdeligi);

        let n = SAPMA_ADLARI.len();
        let sutun = |j: usize| -> Vec<f64> { kayitlar.iter().map(|k| k.sapma_girdi[j]).collect() };
        let medyan: Vec<f64> = (0..n).map(|j| yuzdelik(&sutun(j), 50.0)).collect();
        let olcek: Vec<f64> = (0..n)
            .map(|j| {
                let s = sutun(j);
                (yuzdelik(&s, 75.0) - yuzdelik(&s, 25.0)).max(MIN_OLCEK)
            })
            .collect();

        let mut d = Dedektor { orman, orman_esik, medyan, olcek, sapma_esik: 0.0, egitim_akis: kayitlar.len() };
        let max_z: Vec<f64> = kayitlar.iter().map(|k| d.z_degerleri(k).0).collect();
        d.sapma_esik = yuzdelik(&max_z, 99.5).max(MIN_Z_ESIK);
        d
    }

    /// Sadece yukarı yönlü sapma: "normalden fazla" olan şüpheli. (en büyük z, hangi özellik)
    fn z_degerleri(&self, k: &AkisKaydi) -> (f64, usize) {
        let mut en = (0.0, 0);
        for j in 0..self.medyan.len() {
            let z = ((k.sapma_girdi[j] - self.medyan[j]) / self.olcek[j]).max(0.0);
            if z > en.0 {
                en = (z, j);
            }
        }
        en
    }

    pub fn skorla(&self, k: &AkisKaydi) -> Sonuc {
        let skor = self.orman.skor(&k.ozellik);
        let (sapma, j) = self.z_degerleri(k);
        let mut nedenler = Vec::new();
        if sapma > self.sapma_esik {
            let (_, aciklama) = SAPMA_ADLARI[j];
            nedenler.push(if sapma_ham_sayim_mi(j) {
                format!("{aciklama}: {:.0} (normalde ~{:.0})", k.sapma_girdi[j], self.medyan[j])
            } else {
                format!("{aciklama} normalin çok üstünde")
            });
        }
        if skor > self.orman_esik {
            nedenler.push("alışılmadık akış profili".into());
        }
        let risk = (skor / self.orman_esik).max(sapma / self.sapma_esik).max(0.0);
        Sonuc { skor, sapma, anomali: !nedenler.is_empty(), neden: nedenler.join("; "), risk }
    }

    pub fn kaydet(&self, yol: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(yol, serde_json::to_vec(self)?)
    }

    pub fn yukle(yol: &std::path::Path) -> std::io::Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(yol)?)?)
    }
}

#[cfg(test)]
mod testler {
    use super::*;

    #[test]
    fn yuzdelik_numpy_ile_ayni() {
        let v = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(yuzdelik(&v, 50.0), 2.5);
        assert!((yuzdelik(&v, 75.0) - 3.25).abs() < 1e-12);
        assert_eq!(yuzdelik(&v, 100.0), 4.0);
    }
}
