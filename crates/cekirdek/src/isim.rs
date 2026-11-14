//! Bağlantıların alan adını pasif olarak bulmak: DNS cevapları ve TLS SNI.
//!
//! Hiçbir sorgu gönderilmez; zaten ağdan geçen paketler okunur.
//!   - DNS cevabı (UDP 53): "github.com → 140.82.114.21" eşlemesi
//!   - TLS ClientHello: HTTPS bağlantısının ilk paketinde açık yazılan sunucu adı (SNI)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn u16_be(v: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*v.get(i)?, *v.get(i + 1)?]))
}

/// DNS adını okur (sıkıştırma işaretçileriyle). Döner: (ad, adın paketteki bitişi).
fn dns_adi(paket: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut parcalar: Vec<String> = Vec::new();
    let mut bitis = None;
    let mut atlama = 0;
    loop {
        let uzunluk = *paket.get(i)? as usize;
        if uzunluk == 0 {
            bitis.get_or_insert(i + 1);
            break;
        }
        if uzunluk & 0xc0 == 0xc0 {
            // işaretçi: adın geri kalanı başka yerde
            let hedef = (u16_be(paket, i)? & 0x3fff) as usize;
            bitis.get_or_insert(i + 2);
            atlama += 1;
            if atlama > 20 {
                return None; // döngüye giren bozuk paket
            }
            i = hedef;
            continue;
        }
        let etiket = paket.get(i + 1..i + 1 + uzunluk)?;
        parcalar.push(String::from_utf8_lossy(etiket).to_lowercase());
        i += 1 + uzunluk;
        if parcalar.len() > 64 {
            return None;
        }
    }
    Some((parcalar.join("."), bitis?))
}

/// DNS cevabındaki adres kayıtları: (IP, sorulan ad). CNAME zinciri ne olursa olsun
/// kullanıcıya tanıdık gelen ilk sorulan ad döner (ör. www.youtube.com).
pub fn dns_cevabi(paket: &[u8]) -> Vec<(IpAddr, String)> {
    (|| -> Option<Vec<(IpAddr, String)>> {
        let bayrak = u16_be(paket, 2)?;
        if bayrak & 0x8000 == 0 || bayrak & 0x000f != 0 {
            return None; // cevap değil ya da hata
        }
        let soru = u16_be(paket, 4)?;
        let cevap = u16_be(paket, 6)?;
        if soru != 1 || cevap == 0 {
            return None;
        }
        let (ad, mut i) = dns_adi(paket, 12)?;
        i += 4; // tür + sınıf
        let mut sonuc = Vec::new();
        for _ in 0..cevap.min(64) {
            let (_, j) = dns_adi(paket, i)?;
            let tur = u16_be(paket, j)?;
            let uzunluk = u16_be(paket, j + 8)? as usize;
            let veri = paket.get(j + 10..j + 10 + uzunluk);
            match (tur, veri) {
                (1, Some(v)) if uzunluk == 4 => sonuc.push((IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3])), ad.clone())),
                (28, Some(v)) if uzunluk == 16 => {
                    let b: [u8; 16] = v.try_into().ok()?;
                    sonuc.push((IpAddr::V6(Ipv6Addr::from(b)), ad.clone()));
                }
                (_, None) => break, // kırpılmış paket
                _ => {}
            }
            i = j + 10 + uzunluk;
        }
        Some(sonuc)
    })()
    .unwrap_or_default()
}

/// mDNS (Bonjour, UDP 5353) duyurularındaki cihaz adları: (IP, "Furkan-iPhone").
/// mDNS cevaplarında soru bölümü genelde boştur; adresler cevap veya ek bölümde gelir.
pub fn mdns_adlari(paket: &[u8]) -> Vec<(IpAddr, String)> {
    (|| -> Option<Vec<(IpAddr, String)>> {
        if u16_be(paket, 2)? & 0x8000 == 0 {
            return None;
        }
        let soru = u16_be(paket, 4)?;
        let kayit = u16_be(paket, 6)? as usize + u16_be(paket, 8)? as usize + u16_be(paket, 10)? as usize;
        let mut i = 12;
        for _ in 0..soru.min(32) {
            i = dns_adi(paket, i)?.1 + 4;
        }
        let mut sonuc = Vec::new();
        for _ in 0..kayit.min(64) {
            let (ad, j) = dns_adi(paket, i)?;
            let tur = u16_be(paket, j)?;
            let uzunluk = u16_be(paket, j + 8)? as usize;
            let veri = paket.get(j + 10..j + 10 + uzunluk)?;
            if let Some(cihaz) = ad.strip_suffix(".local") {
                match tur {
                    1 if uzunluk == 4 => {
                        sonuc.push((IpAddr::V4(Ipv4Addr::new(veri[0], veri[1], veri[2], veri[3])), cihaz.to_string()))
                    }
                    28 if uzunluk == 16 => {
                        let b: [u8; 16] = veri.try_into().ok()?;
                        sonuc.push((IpAddr::V6(Ipv6Addr::from(b)), cihaz.to_string()));
                    }
                    _ => {}
                }
            }
            i = j + 10 + uzunluk;
        }
        Some(sonuc)
    })()
    .unwrap_or_default()
}

/// TLS ClientHello'dan SNI. Veri eksikse (ClientHello birden çok pakete bölünmüşse)
/// `Err(gereken_toplam_boy)` döner; çağıran bir sonraki paketi ekleyip tekrar dener.
pub fn tls_sni(veri: &[u8]) -> Result<Option<String>, usize> {
    // TLS kaydı: tür 22 (el sıkışma), sürüm 3.x
    if veri.len() < 6 || veri[0] != 22 || veri[1] != 3 || veri[5] != 1 {
        return Ok(None);
    }
    let kayit_boyu = u16_be(veri, 3).unwrap() as usize + 5;
    let gereken = kayit_boyu.min(16 * 1024);
    let sonuc = (|| -> Option<Option<String>> {
        let mut i = 5 + 4 + 2 + 32; // el sıkışma başlığı, sürüm, rastgele
        i += 1 + *veri.get(i)? as usize; // oturum kimliği
        i += 2 + u16_be(veri, i)? as usize; // şifre takımları
        i += 1 + *veri.get(i)? as usize; // sıkıştırma
        let uzanti_sonu = i + 2 + u16_be(veri, i)? as usize;
        i += 2;
        while i + 4 <= uzanti_sonu {
            let tur = u16_be(veri, i)?;
            let boy = u16_be(veri, i + 2)? as usize;
            if tur == 0 {
                // server_name: liste boyu(2), ad türü(1), ad boyu(2), ad
                let ad_boyu = u16_be(veri, i + 7)? as usize;
                let ad = veri.get(i + 9..i + 9 + ad_boyu)?;
                return Some(Some(String::from_utf8_lossy(ad).to_lowercase()));
            }
            i += 4 + boy;
        }
        // uzantılar okundu, SNI yok
        if i <= veri.len() { Some(None) } else { None }
    })();
    match sonuc {
        Some(s) => Ok(s),
        None if veri.len() < gereken => Err(gereken),
        None => Ok(None),
    }
}

#[cfg(test)]
mod testler {
    use super::*;

    #[test]
    fn dns_cevabi_cname_ile() {
        // soru: www.ornek.com A; cevaplar: CNAME → cdn.ornek.net, A 1.2.3.4
        let mut p = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        p.extend(b"\x03www\x05ornek\x03com\x00");
        p.extend([0, 1, 0, 1]);
        p.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 15]);
        p.extend(b"\x03cdn\x05ornek\x03net\x00");
        let cname_konum = p.len() - 15;
        p.extend([0xc0, cname_konum as u8, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let c = dns_cevabi(&p);
        assert_eq!(c, vec![(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), "www.ornek.com".to_string())]);
    }

    fn client_hello(sni: &str, dolgu: usize) -> Vec<u8> {
        let mut uzantilar = Vec::new();
        // önce büyük bir dolgu uzantısı (Chrome'un key_share'i gibi), sonra SNI
        uzantilar.extend([0x00, 0x15]);
        uzantilar.extend((dolgu as u16).to_be_bytes());
        uzantilar.extend(vec![0; dolgu]);
        let ad = sni.as_bytes();
        uzantilar.extend([0, 0]);
        uzantilar.extend(((ad.len() + 5) as u16).to_be_bytes());
        uzantilar.extend(((ad.len() + 3) as u16).to_be_bytes());
        uzantilar.push(0);
        uzantilar.extend((ad.len() as u16).to_be_bytes());
        uzantilar.extend(ad);
        let mut govde = vec![3, 3];
        govde.extend([7; 32]);
        govde.push(0);
        govde.extend([0, 2, 0x13, 0x01]);
        govde.extend([1, 0]);
        govde.extend((uzantilar.len() as u16).to_be_bytes());
        govde.extend(uzantilar);
        let mut hs = vec![1, 0];
        hs.extend((govde.len() as u16).to_be_bytes());
        hs.extend(govde);
        let mut kayit = vec![22, 3, 1];
        kayit.extend((hs.len() as u16).to_be_bytes());
        kayit.extend(hs);
        kayit
    }

    #[test]
    fn sni_okunur() {
        assert_eq!(tls_sni(&client_hello("api.github.com", 10)), Ok(Some("api.github.com".into())));
    }

    #[test]
    fn bolunmus_client_hello() {
        let tam = client_hello("www.apple.com", 1800);
        let ilk = &tam[..1400];
        assert_eq!(tls_sni(ilk), Err(tam.len()));
        assert_eq!(tls_sni(&tam), Ok(Some("www.apple.com".into())));
    }

    #[test]
    fn mdns_cihaz_adi() {
        // soru yok, 1 cevap: furkan-iphone.local A 192.168.1.40
        let mut p = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        p.extend(b"\x0dfurkan-iphone\x05local\x00");
        p.extend([0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 40]);
        assert_eq!(mdns_adlari(&p), vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)), "furkan-iphone".to_string())]);
    }

    #[test]
    fn tls_olmayan_veri() {
        assert_eq!(tls_sni(b"GET / HTTP/1.1\r\n"), Ok(None));
    }
}
