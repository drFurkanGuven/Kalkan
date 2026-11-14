//! Isolation Forest (Liu, Ting & Zhou, 2008).
//!
//! Her ağaç, veriyi rastgele bir özellik ve o özelliğin aralığında rastgele bir
//! eşikle ikiye böler. Normal noktalar kalabalık olduğu için yalnız kalmaları
//! derin bir yol gerektirir; aykırı noktalar birkaç bölmede yalnız kalır.
//! Skor = 2^(-ortalama yol / c(n)) - 0.5  (scikit-learn'ün -decision_function'ı ile aynı ölçek).

use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

const EULER: f64 = std::f64::consts::EULER_GAMMA;

/// n noktalı rastgele bir ikili ağaçta başarısız aramanın ortalama yol uzunluğu.
fn c(n: usize) -> f64 {
    match n {
        0 | 1 => 0.0,
        2 => 1.0,
        _ => {
            let n = n as f64;
            2.0 * ((n - 1.0).ln() + EULER) - 2.0 * (n - 1.0) / n
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Dugum {
    Ic { ozellik: u16, esik: f64, sol: u32, sag: u32 },
    Yaprak { boyut: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Agac {
    dugumler: Vec<Dugum>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsolationForest {
    agaclar: Vec<Agac>,
    ornek_sayisi: usize,
}

impl IsolationForest {
    /// `veri`: her satır bir örnek. Aynı tohumla her zaman aynı model çıkar.
    pub fn egit(veri: &[Vec<f64>], agac_sayisi: usize, tohum: u64) -> Self {
        assert!(!veri.is_empty(), "boş veriyle eğitilemez");
        let mut rng = ChaCha8Rng::seed_from_u64(tohum);
        let ornek_sayisi = veri.len().min(256);
        let max_derinlik = (ornek_sayisi as f64).log2().ceil() as usize;

        let agaclar = (0..agac_sayisi)
            .map(|_| {
                // yerine koymadan örnekleme (kısmi Fisher-Yates)
                let mut idx: Vec<usize> = (0..veri.len()).collect();
                for i in 0..ornek_sayisi {
                    let j = rng.random_range(i..idx.len());
                    idx.swap(i, j);
                }
                idx.truncate(ornek_sayisi);
                let mut agac = Agac { dugumler: Vec::new() };
                agac_kur(&mut agac, veri, &mut idx, 0, max_derinlik, &mut rng);
                agac
            })
            .collect();
        IsolationForest { agaclar, ornek_sayisi }
    }

    /// Yüksek = daha anormal. Aralık yaklaşık -0.5 .. 0.5.
    pub fn skor(&self, x: &[f64]) -> f64 {
        let toplam: f64 = self.agaclar.iter().map(|a| yol_uzunlugu(a, x)).sum();
        let ort = toplam / self.agaclar.len() as f64;
        2f64.powf(-ort / c(self.ornek_sayisi)) - 0.5
    }
}

fn agac_kur(
    agac: &mut Agac,
    veri: &[Vec<f64>],
    idx: &mut [usize],
    derinlik: usize,
    max_derinlik: usize,
    rng: &mut ChaCha8Rng,
) -> u32 {
    let konum = agac.dugumler.len() as u32;
    let yaprak = Dugum::Yaprak { boyut: idx.len() as u32 };
    if derinlik >= max_derinlik || idx.len() <= 1 {
        agac.dugumler.push(yaprak);
        return konum;
    }

    // Bu düğümde sabit olmayan özellikler arasından rastgele seç
    let boyut = veri[0].len();
    let araliklar: Vec<(usize, f64, f64)> = (0..boyut)
        .filter_map(|f| {
            let (mut lo, mut hi) = (f64::INFINITY, f64::NEG_INFINITY);
            for &i in idx.iter() {
                lo = lo.min(veri[i][f]);
                hi = hi.max(veri[i][f]);
            }
            (hi > lo).then_some((f, lo, hi))
        })
        .collect();
    if araliklar.is_empty() {
        agac.dugumler.push(yaprak);
        return konum;
    }
    let (ozellik, lo, hi) = araliklar[rng.random_range(0..araliklar.len())];
    let esik = lo + rng.random::<f64>() * (hi - lo);

    // idx'i yerinde böl: esik'e eşit veya küçükler sola
    let mut sinir = 0;
    for i in 0..idx.len() {
        if veri[idx[i]][ozellik] <= esik {
            idx.swap(i, sinir);
            sinir += 1;
        }
    }
    agac.dugumler.push(Dugum::Ic { ozellik: ozellik as u16, esik, sol: 0, sag: 0 });
    let (sol_idx, sag_idx) = idx.split_at_mut(sinir);
    let sol = agac_kur(agac, veri, sol_idx, derinlik + 1, max_derinlik, rng);
    let sag = agac_kur(agac, veri, sag_idx, derinlik + 1, max_derinlik, rng);
    if let Dugum::Ic { sol: s, sag: g, .. } = &mut agac.dugumler[konum as usize] {
        *s = sol;
        *g = sag;
    }
    konum
}

fn yol_uzunlugu(agac: &Agac, x: &[f64]) -> f64 {
    let mut i = 0usize;
    let mut derinlik = 0.0;
    loop {
        match &agac.dugumler[i] {
            Dugum::Yaprak { boyut } => return derinlik + c(*boyut as usize),
            Dugum::Ic { ozellik, esik, sol, sag } => {
                i = if x[*ozellik as usize] <= *esik { *sol } else { *sag } as usize;
                derinlik += 1.0;
            }
        }
    }
}

#[cfg(test)]
mod testler {
    use super::*;

    #[test]
    fn aykiri_nokta_daha_yuksek_skor_alir() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let veri: Vec<Vec<f64>> = (0..500)
            .map(|_| vec![rng.random::<f64>(), rng.random::<f64>()])
            .collect();
        let orman = IsolationForest::egit(&veri, 100, 42);
        let normal = orman.skor(&[0.5, 0.5]);
        let aykiri = orman.skor(&[5.0, 5.0]);
        assert!(aykiri > normal + 0.1, "aykırı {aykiri:.3} normal {normal:.3}");
    }

    #[test]
    fn ayni_tohum_ayni_model() {
        let veri: Vec<Vec<f64>> = (0..300).map(|i| vec![i as f64, (i % 7) as f64]).collect();
        let a = IsolationForest::egit(&veri, 50, 7).skor(&[10.0, 3.0]);
        let b = IsolationForest::egit(&veri, 50, 7).skor(&[10.0, 3.0]);
        assert_eq!(a, b);
    }
}
