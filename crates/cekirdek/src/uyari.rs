//! Tek tek anomali akışlarını anlamlı uyarılara gruplar.
//!
//! Bir port taraması 1000 anomali akışı üretir; kullanıcı bunu tek bir
//! "Port taraması şüphesi" uyarısı olarak görmeli. Aynı kaynak IP + aynı tür,
//! aralarında 5 dakikadan az boşluk varsa tek uyarıdır.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use serde::Serialize;

pub const BOSLUK_US: u64 = 5 * 60 * 1_000_000;

/// (neden metninde aranan ifade, başlık, açıklama). İlk eşleşen kazanır.
pub const TURLER: [(&str, &str, &str); 9] = [
    ("açık port", "Yeni açık port",
     "Bu Mac'te ağdan erişilebilen yeni bir servis açıldı (paylaşım ayarı, geliştirme sunucusu veya arka kapı olabilir)."),
    ("ARP sahteciliği", "Ortadaki adam (ARP sahteciliği) şüphesi",
     "Ağda biri kendini ağ geçidi gibi tanıtıyor; trafiğin onun üzerinden geçiyor olabilir."),
    ("ARP taraması", "Yerel ağ taraması (ARP)",
     "Bir cihaz kısa sürede yerel ağdaki çok sayıda adresi yokladı (nmap -sn, netdiscover gibi)."),
    ("farklı port", "Port taraması şüphesi",
     "Tek bir kaynak kısa sürede çok sayıda farklı porta bağlanmaya çalıştı."),
    ("farklı hedef", "Yayılma / ağ taraması şüphesi",
     "Tek bir kaynak kısa sürede çok sayıda farklı cihaza bağlandı."),
    ("başarısız bağlantı", "Çok sayıda başarısız bağlantı",
     "Bağlantılar reddediliyor veya cevapsız kalıyor (tarama, kaba kuvvet veya ağ sorunu)."),
    ("akış sayısı", "Bağlantı seli",
     "Tek bir kaynak normalin çok üstünde bağlantı açtı (DoS, kaba kuvvet veya hatalı uygulama)."),
    ("veri", "Alışılmadık veri aktarımı",
     "Bir akışta normalin çok üstünde veri aktarıldı (büyük indirme veya veri sızdırma)."),
    ("", "Alışılmadık bağlantı", "Akışın genel profili normal trafiğe benzemiyor."),
];

/// Bu uyarı türünü üreten davranışın tipik olarak hangi yerel ağ / pentest araçlarıyla
/// yapıldığı. Aracı kesin söylemez; davranışın bilinen kaynaklarını sıralar.
/// (başlık, araçlar, ne yaptığı)
pub fn pentest_ipucu(tur: &str) -> Option<(&'static str, &'static str)> {
    Some(match tur {
        "Yerel ağ taraması (ARP)" => (
            "nmap -sn · netdiscover · arp-scan · Fing",
            "Ağdaki cihazları ARP ile listeleme (keşif). Bir saldırının ilk adımı olabilir.",
        ),
        "Ortadaki adam (ARP sahteciliği) şüphesi" => (
            "ettercap · bettercap · arpspoof · mitmproxy",
            "Ağ geçidini taklit edip trafiği dinleme/değiştirme (man-in-the-middle).",
        ),
        "Port taraması şüphesi" => (
            "nmap · masscan · rustscan · zmap",
            "Bir cihazda açık servisleri arama. Zafiyet taramasının ilk adımı.",
        ),
        "Yayılma / ağ taraması şüphesi" => (
            "nmap · masscan · zmap",
            "Ağ genelinde çok sayıda cihazı tarama.",
        ),
        "Çok sayıda başarısız bağlantı" => (
            "hydra · medusa · ncrack · nmap",
            "Parola deneme (kaba kuvvet) ya da kapalı portlara tarama.",
        ),
        _ => return None,
    })
}

pub fn tur_bul(neden: &str) -> (&'static str, &'static str) {
    TURLER
        .iter()
        .find(|(anahtar, _, _)| neden.contains(anahtar))
        .map(|(_, b, a)| (*b, *a))
        .unwrap()
}

/// Gruplamaya giren bir anomali akışı.
pub struct AnomaliAkisi {
    pub zaman_us: u64,
    pub kaynak: IpAddr,
    pub hedef: IpAddr,
    pub hedef_port: u16,
    pub risk: f64,
    pub sapma: f64,
    pub neden: String,
    /// bağlantıyı açan uygulama (biliniyorsa)
    pub surec: Option<String>,
    /// karşı tarafın alan adı (DNS / SNI'den)
    pub alan_adi: Option<String>,
}

/// En sık görülen dolu değer.
fn en_sik<'a>(degerler: impl Iterator<Item = &'a Option<String>>) -> Option<String> {
    let mut say: HashMap<&str, usize> = HashMap::new();
    degerler.flatten().for_each(|d| *say.entry(d.as_str()).or_default() += 1);
    say.into_iter().max_by_key(|(d, n)| (*n, std::cmp::Reverse(*d))).map(|(d, _)| d.to_string())
}

#[derive(Clone, Debug, Serialize)]
pub struct Uyari {
    pub tur: &'static str,
    pub aciklama: &'static str,
    pub kaynak: IpAddr,
    pub ilk_us: u64,
    pub son_us: u64,
    pub akis: usize,
    pub hedef_sayisi: usize,
    pub port_sayisi: usize,
    pub hedefler: Vec<IpAddr>,
    pub risk: f64,
    pub ornek_neden: String,
    pub surec: Option<String>,
    pub alan_adi: Option<String>,
    /// Bu davranışı üreten tipik pentest araçları (varsa)
    pub arac_ipucu: Option<&'static str>,
    pub arac_aciklama: Option<&'static str>,
}

/// En riskli uyarı önce.
pub fn grupla(mut akislar: Vec<AnomaliAkisi>) -> Vec<Uyari> {
    akislar.sort_by_key(|a| a.zaman_us);
    let mut gruplar: BTreeMap<(IpAddr, &'static str), Vec<Vec<AnomaliAkisi>>> = BTreeMap::new();
    for a in akislar {
        let tur = tur_bul(&a.neden).0;
        let liste = gruplar.entry((a.kaynak, tur)).or_default();
        match liste.last_mut() {
            Some(son) if a.zaman_us - son.last().unwrap().zaman_us <= BOSLUK_US => son.push(a),
            _ => liste.push(vec![a]),
        }
    }

    let mut uyarilar: Vec<Uyari> = gruplar
        .into_iter()
        .flat_map(|((kaynak, tur), parcalar)| {
            parcalar.into_iter().map(move |p| {
                let mut hedef_say: HashMap<IpAddr, usize> = HashMap::new();
                p.iter().for_each(|a| *hedef_say.entry(a.hedef).or_default() += 1);
                let mut hedefler: Vec<(IpAddr, usize)> = hedef_say.into_iter().collect();
                hedefler.sort_by_key(|h| std::cmp::Reverse(h.1));
                let ornek = p.iter().max_by(|a, b| a.sapma.total_cmp(&b.sapma)).unwrap();
                Uyari {
                    tur,
                    aciklama: tur_bul(&ornek.neden).1,
                    kaynak,
                    ilk_us: p.first().unwrap().zaman_us,
                    son_us: p.last().unwrap().zaman_us,
                    akis: p.len(),
                    hedef_sayisi: hedefler.len(),
                    port_sayisi: p.iter().map(|a| a.hedef_port).collect::<HashSet<_>>().len(),
                    hedefler: hedefler.into_iter().take(3).map(|h| h.0).collect(),
                    risk: p.iter().map(|a| a.risk).fold(0.0, f64::max),
                    ornek_neden: ornek.neden.clone(),
                    surec: en_sik(p.iter().map(|a| &a.surec)),
                    alan_adi: en_sik(p.iter().map(|a| &a.alan_adi)),
                    arac_ipucu: pentest_ipucu(tur).map(|(a, _)| a),
                    arac_aciklama: pentest_ipucu(tur).map(|(_, a)| a),
                }
            })
        })
        .collect();
    uyarilar.sort_by(|a, b| b.risk.total_cmp(&a.risk).then(b.son_us.cmp(&a.son_us)));
    uyarilar
}
