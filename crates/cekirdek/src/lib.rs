//! Kalkan çekirdeği: paket → akış → özellik → anomali skoru → uyarı.
//!
//! Arayüzden ve yakalama yönteminden bağımsız; hem komut satırı aracı hem
//! arka plan servisi bu kütüphaneyi kullanır.

pub mod akis;
pub mod dedektor;
pub mod isim;
pub mod kaynak;
pub mod orman;
pub mod ozellik;
pub mod paket;
pub mod uyari;

pub use akis::{Akis, AkisTablosu};
pub use dedektor::{Dedektor, Sonuc};
pub use ozellik::{AkisKaydi, Pencere};
