//! Ham paket baytlarından IP / TCP / UDP başlıklarını okur.
//!
//! Bilinçli olarak küçük ve hoşgörülü: 512 bayta kırpılmış paketlerde de
//! çalışır, tanımadığı her şeyi sessizce atlar.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const ICMP: u8 = 1;
pub const ICMPV6: u8 = 58;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;

/// Bağlantı katmanı türü (pcap "linktype").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Baglanti {
    /// Ethernet II (kablolu / Wi-Fi arayüzleri)
    Ethernet,
    /// Doğrudan IP ile başlar (VPN tünelleri, utun)
    HamIp,
    /// 4 baytlık adres ailesi başlığı (loopback, BSD NULL/LOOP)
    Null,
}

#[derive(Clone, Debug)]
pub struct Paket<'a> {
    /// Unix zamanı, mikro saniye
    pub zaman_us: u64,
    pub kaynak: IpAddr,
    pub hedef: IpAddr,
    pub kaynak_port: u16,
    pub hedef_port: u16,
    pub protokol: u8,
    /// IP başlığındaki toplam uzunluk (kırpmadan bağımsız gerçek boy)
    pub ip_boyu: u32,
    pub tcp_bayrak: u8,
    /// Taşıma katmanı yükü (DNS/TLS çözümlemesi için; kırpılmış olabilir)
    pub yuk: &'a [u8],
}

fn u16_be(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Bağlantı katmanından başlayarak paketi çözer.
pub fn coz<'a>(baglanti: Baglanti, veri: &'a [u8], zaman_us: u64) -> Option<Paket<'a>> {
    let ip = match baglanti {
        Baglanti::HamIp => veri,
        Baglanti::Null => veri.get(4..)?,
        Baglanti::Ethernet => {
            let mut tip = u16_be(veri, 12)?;
            let mut ofset = 14;
            while tip == 0x8100 || tip == 0x88a8 {
                // VLAN etiketi
                tip = u16_be(veri, ofset + 2)?;
                ofset += 4;
            }
            if tip != 0x0800 && tip != 0x86dd {
                return None;
            }
            veri.get(ofset..)?
        }
    };
    ip_coz(ip, zaman_us)
}

/// Bir ARP paketi (sadece Ethernet + IPv4). "gönderen" alanları, gönderenin iddiasıdır:
/// sahte ARP'de saldırgan "ağ geçidi benim" der.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ArpPaket {
    /// 1 = istek ("X kimde?"), 2 = cevap ("X bende")
    pub islem: u16,
    pub gonderen_mac: [u8; 6],
    pub gonderen_ip: Ipv4Addr,
    pub hedef_ip: Ipv4Addr,
}

pub const ARP_ISTEK: u16 = 1;
pub const ARP_CEVAP: u16 = 2;

/// Ethernet çerçevesinden ARP çözer; ARP değilse None.
pub fn arp_coz(veri: &[u8]) -> Option<ArpPaket> {
    let mut tip = u16_be(veri, 12)?;
    let mut o = 14;
    while tip == 0x8100 || tip == 0x88a8 {
        tip = u16_be(veri, o + 2)?;
        o += 4;
    }
    if tip != 0x0806 {
        return None;
    }
    let a = veri.get(o..o + 28)?;
    // donanım: Ethernet (1), protokol: IPv4, uzunluklar 6 / 4
    if u16_be(a, 0)? != 1 || u16_be(a, 2)? != 0x0800 || a[4] != 6 || a[5] != 4 {
        return None;
    }
    Some(ArpPaket {
        islem: u16_be(a, 6)?,
        gonderen_mac: a[8..14].try_into().ok()?,
        gonderen_ip: Ipv4Addr::new(a[14], a[15], a[16], a[17]),
        hedef_ip: Ipv4Addr::new(a[24], a[25], a[26], a[27]),
    })
}

pub fn mac_yazi(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn ip_coz(ip: &[u8], zaman_us: u64) -> Option<Paket<'_>> {
    let surum = ip.first()? >> 4;
    let (kaynak, hedef, mut protokol, ip_boyu, mut ofset) = match surum {
        4 => {
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            if ihl < 20 || ip.len() < 20 {
                return None;
            }
            // Parçalanmış paketlerin sonraki parçalarında port yok: atla
            let parca_ofseti = u16_be(ip, 6)? & 0x1fff;
            if parca_ofseti != 0 {
                return None;
            }
            let k = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
            let h = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            (IpAddr::V4(k), IpAddr::V4(h), ip[9], u16_be(ip, 2)? as u32, ihl)
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            let k: [u8; 16] = ip[8..24].try_into().ok()?;
            let h: [u8; 16] = ip[24..40].try_into().ok()?;
            let boy = u16_be(ip, 4)? as u32 + 40;
            (IpAddr::V6(Ipv6Addr::from(k)), IpAddr::V6(Ipv6Addr::from(h)), ip[6], boy, 40)
        }
        _ => return None,
    };

    // IPv6 uzantı başlıklarını atla
    if surum == 6 {
        while matches!(protokol, 0 | 43 | 60) {
            let sonraki = *ip.get(ofset)?;
            let uzunluk = (*ip.get(ofset + 1)? as usize + 1) * 8;
            protokol = sonraki;
            ofset += uzunluk;
        }
        if protokol == 44 {
            return None; // parçalanmış IPv6
        }
    }

    let tasima = ip.get(ofset..).unwrap_or(&[]);
    let (kaynak_port, hedef_port, tcp_bayrak, yuk) = match protokol {
        TCP => {
            let veri_ofseti = ((*tasima.get(12)? >> 4) as usize) * 4;
            (
                u16_be(tasima, 0)?,
                u16_be(tasima, 2)?,
                *tasima.get(13)?,
                tasima.get(veri_ofseti..).unwrap_or(&[]),
            )
        }
        UDP => (u16_be(tasima, 0)?, u16_be(tasima, 2)?, 0, tasima.get(8..).unwrap_or(&[])),
        _ => (0, 0, 0, &[][..]),
    };

    Some(Paket { zaman_us, kaynak, hedef, kaynak_port, hedef_port, protokol, ip_boyu, tcp_bayrak, yuk })
}

#[cfg(test)]
mod testler {
    use super::*;

    #[test]
    fn ipv4_tcp_syn_cozulur() {
        // 20 bayt IPv4 + 20 bayt TCP, SYN bayraklı, 10.0.0.1:40000 -> 10.0.0.2:80
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        p.extend_from_slice(&[0x9c, 0x40, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0]);
        let k = coz(Baglanti::HamIp, &p, 0).unwrap();
        assert_eq!(k.kaynak.to_string(), "10.0.0.1");
        assert_eq!((k.kaynak_port, k.hedef_port, k.protokol), (40000, 80, TCP));
        assert_eq!(k.tcp_bayrak & SYN, SYN);
        assert_eq!(k.ip_boyu, 40);
    }

    #[test]
    fn kirpilmis_paket_cokmez() {
        let p = [0x45, 0, 0, 40, 0, 0];
        assert!(coz(Baglanti::HamIp, &p, 0).is_none());
    }

    #[test]
    fn arp_cevabi_cozulur() {
        let mut c = vec![0xff; 6];
        c.extend([0x66; 6]);
        c.extend([0x08, 0x06]);
        c.extend([0, 1, 0x08, 0, 6, 4, 0, 2]);
        c.extend([0x66; 6]);
        c.extend([192, 168, 1, 1]);
        c.extend([0xaa; 6]);
        c.extend([192, 168, 1, 10]);
        let a = arp_coz(&c).unwrap();
        assert_eq!(a.islem, ARP_CEVAP);
        assert_eq!(a.gonderen_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(mac_yazi(&a.gonderen_mac), "66:66:66:66:66:66");
        assert!(coz(Baglanti::Ethernet, &c, 0).is_none());
    }
}
