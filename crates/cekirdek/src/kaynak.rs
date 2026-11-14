//! .pcap dosyasından akış üretir.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use pcap_file::DataLink;
use pcap_file::pcap::PcapReader;

use crate::akis::{Akis, AkisTablosu};
use crate::paket::{self, Baglanti};

pub fn baglanti_turu(dl: DataLink) -> Option<Baglanti> {
    match dl {
        DataLink::ETHERNET => Some(Baglanti::Ethernet),
        DataLink::RAW | DataLink::IPV4 | DataLink::IPV6 => Some(Baglanti::HamIp),
        DataLink::NULL | DataLink::LOOP => Some(Baglanti::Null),
        _ => None,
    }
}

/// Dosyadaki paketleri okur, akışlara birleştirir ve her kapanan akışı `cikis`a verir.
pub fn pcap_akislari(yol: &Path, mut cikis: impl FnMut(Akis)) -> Result<PcapOzeti, String> {
    let dosya = File::open(yol).map_err(|e| format!("{}: {e}", yol.display()))?;
    let mut okuyucu = PcapReader::new(BufReader::new(dosya)).map_err(|e| format!("pcap okunamadı: {e}"))?;
    let dl = okuyucu.header().datalink;
    let baglanti = baglanti_turu(dl).ok_or_else(|| format!("desteklenmeyen bağlantı türü: {dl:?}"))?;

    let mut tablo = AkisTablosu::new();
    let mut ozet = PcapOzeti::default();
    while let Some(p) = okuyucu.next_packet() {
        let p = p.map_err(|e| format!("bozuk paket: {e}"))?;
        ozet.paket += 1;
        let zaman_us = p.timestamp().as_micros() as u64;
        match paket::coz(baglanti, p.data(), zaman_us) {
            Some(k) => tablo.ekle(&k, &mut cikis),
            None => ozet.atlanan += 1,
        }
    }
    tablo.hepsini_ver(&mut cikis);
    Ok(ozet)
}

#[derive(Debug, Default)]
pub struct PcapOzeti {
    pub paket: u64,
    pub atlanan: u64,
}
