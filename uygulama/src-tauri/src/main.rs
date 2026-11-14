//! Kalkan menü çubuğu uygulaması.
//!
//! Menü çubuğunda bir kalkan simgesi durur; tıklayınca açılır panel gelir.
//! Arka planda 5 sn'de bir servise sorar, yeni uyarı gelince bildirim gösterir
//! ve görülmemiş uyarı varken simgeyi kırmızıya çevirir.
//!
//! Servisle konuşma: root servisin Unix soketi üzerinden tek satır JSON.
//! Soket yolu KALKAN_SOKET ortam değişkeniyle değiştirilebilir (test için).

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, Rect, WebviewWindow, WindowEvent, Wry};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_notification::NotificationExt;

const VARSAYILAN_SOKET: &str = "/Library/Application Support/Kalkan/kalkan.sock";
const TEPSI: &[u8] = include_bytes!("../icons/tepsi.png");
const TEPSI_UYARI: &[u8] = include_bytes!("../icons/tepsi-uyari.png");
/// Bu riskin altındaki uyarılar bildirim göndermez (paneldeki "Düşük" seviye).
const BILDIRIM_RISKI: f64 = 3.0;

/// Panelin en son açıldığı an (ms). Bundan yeni uyarılar "görülmemiş" sayılır.
static SON_BAKIS_MS: AtomicU64 = AtomicU64::new(0);
/// Panel odağı kaybedip gizlendiği an (ms). Simgeye tıklayınca hemen tekrar açılmasın diye.
static GIZLENME_MS: AtomicU64 = AtomicU64::new(0);

fn simdi_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn soket_yolu() -> PathBuf {
    std::env::var_os("KALKAN_SOKET").map(PathBuf::from).unwrap_or_else(|| VARSAYILAN_SOKET.into())
}

fn servise_sor(istek: &Value) -> Result<Value, String> {
    let mut akim = UnixStream::connect(soket_yolu()).map_err(|_| "servis_kapali".to_string())?;
    akim.set_read_timeout(Some(Duration::from_secs(10))).ok();
    writeln!(akim, "{istek}").map_err(|e| e.to_string())?;
    let mut satir = String::new();
    BufReader::new(akim).read_line(&mut satir).map_err(|e| e.to_string())?;
    let cevap: Value = serde_json::from_str(&satir).map_err(|e| format!("geçersiz cevap: {e}"))?;
    if let Some(hata) = cevap.get("hata").and_then(Value::as_str) {
        return Err(hata.to_string());
    }
    Ok(cevap)
}

/// Arayüzün servise sorduğu tek komut.
#[tauri::command]
async fn sor(istek: Value) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || servise_sor(&istek))
        .await
        .map_err(|e| e.to_string())?
}

/// Arayüz panel içeriğini çizdikten sonra uyarıları görüldü say.
#[tauri::command]
fn goruldu(app: AppHandle) {
    SON_BAKIS_MS.store(simdi_ms(), Ordering::Relaxed);
    if let Some(tepsi) = app.tray_by_id("kalkan") {
        tepsi_simgesi(&tepsi, 0);
    }
}

fn panel(app: &AppHandle) -> Option<WebviewWindow> {
    app.get_webview_window("panel")
}

fn panel_goster(app: &AppHandle, simge: Option<Rect>) {
    let Some(p) = panel(app) else { return };
    if let (Some(rect), Ok(olcek), Ok(boyut)) = (simge, p.scale_factor(), p.outer_size()) {
        // Paneli simgenin altına, ortalayarak yerleştir
        let konum = rect.position.to_physical::<f64>(olcek);
        let simge_boyu = rect.size.to_physical::<f64>(olcek);
        let mut x = konum.x + simge_boyu.width / 2.0 - boyut.width as f64 / 2.0;
        if let Ok(Some(ekran)) = p.current_monitor() {
            let sol = ekran.position().x as f64 + 8.0 * olcek;
            let sag = (ekran.position().x + ekran.size().width as i32) as f64 - boyut.width as f64 - 8.0 * olcek;
            x = x.clamp(sol, sag.max(sol));
        }
        let y = konum.y + simge_boyu.height + 6.0 * olcek;
        let _ = p.set_position(PhysicalPosition::new(x, y));
    } else {
        let _ = p.center();
    }
    let _ = p.show();
    let _ = p.set_focus();
    let _ = p.emit("panel_acildi", ());
}

/// Geniş görünüm penceresini aç / öne getir.
fn pano_ac(app: &AppHandle) {
    if let Some(panel) = panel(app) {
        let _ = panel.hide();
    }
    if let Some(p) = app.get_webview_window("pano") {
        let _ = p.show();
        let _ = p.unminimize();
        let _ = p.set_focus();
        let _ = p.emit("panel_acildi", ());
    }
}

#[tauri::command]
fn panoyu_ac(app: AppHandle) {
    pano_ac(&app);
}

fn panel_degistir(app: &AppHandle, simge: Rect) {
    let Some(p) = panel(app) else { return };
    if p.is_visible().unwrap_or(false) {
        let _ = p.hide();
    } else if simdi_ms().saturating_sub(GIZLENME_MS.load(Ordering::Relaxed)) > 250 {
        // (odak kaybıyla az önce gizlendiyse bu tıklama "kapat" demekti)
        panel_goster(app, Some(simge));
    }
}

fn tepsi_simgesi(tepsi: &TrayIcon<Wry>, gorulmemis: usize) {
    if gorulmemis > 0 {
        let _ = tepsi.set_icon(Image::from_bytes(TEPSI_UYARI).ok());
        let _ = tepsi.set_icon_as_template(false);
        let _ = tepsi.set_title(Some(gorulmemis.to_string()));
    } else {
        let _ = tepsi.set_icon(Image::from_bytes(TEPSI).ok());
        let _ = tepsi.set_icon_as_template(true);
        let _ = tepsi.set_title(None::<&str>);
    }
}

/// Arka plan döngüsü: durum ve uyarıları izler, simgeyi ve bildirimleri günceller.
fn izleyici(app: AppHandle, tepsi: TrayIcon<Wry>, durum_ogesi: MenuItem<Wry>) {
    let mut gorulen: HashSet<String> = HashSet::new();
    let mut ilk_tur = true;
    loop {
        let durum = servise_sor(&json!({"komut": "durum"}));
        let uyarilar = servise_sor(&json!({"komut": "uyarilar", "saat": 24}));

        let (metin, ipucu) = match &durum {
            Err(_) => ("Servis çalışmıyor".to_string(), "Kalkan · servis çalışmıyor".to_string()),
            Ok(d) if d["mod_"] == "ogrenme" => {
                let akis = d["ogrenme_akis"].as_u64().unwrap_or(0);
                (format!("Öğreniyor · {akis} akış"), "Kalkan · ağını öğreniyor".to_string())
            }
            Ok(d) => {
                let arayuz = d["arayuz"].as_str().unwrap_or("-");
                (format!("İzleniyor · {arayuz}"), format!("Kalkan · {arayuz} izleniyor"))
            }
        };
        let _ = durum_ogesi.set_text(metin);
        let _ = tepsi.set_tooltip(Some(ipucu));

        // Bu Mac'in adresleri: başka cihazlar arasındaki olaylar bildirim göndermez
        let yerel: HashSet<String> = durum
            .as_ref()
            .ok()
            .and_then(|d| d["yerel_ipler"].as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        // Düşük riskli uyarılar sadece panelde görünür; bildirim ve kırmızı simge orta/yüksekte
        let liste: Vec<Value> = uyarilar
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter(|u| u["risk"].as_f64().unwrap_or(0.0) >= BILDIRIM_RISKI)
            .filter(|u| beni_ilgilendiriyor(u, &yerel))
            .collect();
        let son_bakis_us = SON_BAKIS_MS.load(Ordering::Relaxed) * 1000;
        let gorulmemis = liste
            .iter()
            .filter(|u| u["son_us"].as_u64().unwrap_or(0) > son_bakis_us)
            .count();
        let panel_acik = panel(&app).and_then(|p| p.is_visible().ok()).unwrap_or(false);
        tepsi_simgesi(&tepsi, if panel_acik { 0 } else { gorulmemis });

        for u in &liste {
            let anahtar = format!("{}|{}|{}", u["kaynak"], u["tur"], u["ilk_us"]);
            if gorulen.insert(anahtar) && !ilk_tur {
                bildirim_goster(&app, u);
            }
        }
        let pano_acik = app.get_webview_window("pano").and_then(|p| p.is_visible().ok()).unwrap_or(false);
        if panel_acik || pano_acik {
            let _ = app.emit("yenile", ());
        }
        ilk_tur = false;
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// Uyarı bu Mac'i ya da bütün ağı ilgilendiriyor mu? (Panel'deki ilgi() ile aynı kural)
fn beni_ilgilendiriyor(u: &Value, yerel: &HashSet<String>) -> bool {
    let tur = u["tur"].as_str().unwrap_or("");
    if tur.contains("ARP") || tur == "Yeni açık port" || yerel.is_empty() {
        return true;
    }
    let kaynak = u["kaynak"].as_str().unwrap_or("");
    yerel.contains(kaynak)
        || u["hedefler"]
            .as_array()
            .is_some_and(|h| h.iter().any(|x| x.as_str().is_some_and(|x| yerel.contains(x))))
}

fn bildirim_goster(app: &AppHandle, u: &Value) {
    let tur = u["tur"].as_str().unwrap_or("Uyarı");
    let kaynak = u["kaynak"].as_str().unwrap_or("?");
    let hedef_sayisi = u["hedef_sayisi"].as_u64().unwrap_or(0);
    let hedef = match u["hedefler"].get(0).and_then(Value::as_str) {
        Some(h) if hedef_sayisi > 1 => format!("{h} ve {} hedef daha", hedef_sayisi - 1),
        Some(h) => h.to_string(),
        None => "?".into(),
    };
    // Biliniyorsa "Uygulama → alan adı", yoksa IP'ler
    let kim = match (u["surec"].as_str(), u["alan_adi"].as_str()) {
        (Some(s), Some(a)) => format!("{s} → {a}"),
        (Some(s), None) => format!("{s} · {kaynak} → {hedef}"),
        (None, Some(a)) => format!("{kaynak} → {a}"),
        _ => format!("{kaynak} → {hedef}"),
    };
    let govde = format!("{kim}\n{}", u["aciklama"].as_str().unwrap_or(""));
    let _ = app.notification().builder().title(format!("⚠ {tur}")).body(govde).show();
}

/// Paketlenmiş uygulama ilk kez açıldığında oturum açılışında başlatmayı aç.
/// (Geliştirme sürümü kendini açılışa kaydetmesin diye sadece release'te.)
fn ilk_acilista_otomatik_baslat(app: &AppHandle) {
    if cfg!(debug_assertions) {
        return;
    }
    let Ok(dizin) = app.path().app_config_dir() else { return };
    let isaret = dizin.join("ilk-acilis-tamam");
    if isaret.exists() {
        return;
    }
    let _ = app.autolaunch().enable();
    let _ = std::fs::create_dir_all(&dizin);
    let _ = std::fs::write(isaret, "");
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, None))
        .invoke_handler(tauri::generate_handler![sor, goruldu, panoyu_ac])
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            ilk_acilista_otomatik_baslat(app.handle());
            let acilista = app.autolaunch().is_enabled().unwrap_or(false);

            let durum_ogesi = MenuItem::with_id(app, "durum", "Bağlanıyor…", false, None::<&str>)?;
            let acilis = CheckMenuItem::with_id(app, "acilis", "Açılışta başlat", true, acilista, None::<&str>)?;
            let ac = MenuItem::with_id(app, "ac", "Paneli aç", true, None::<&str>)?;
            let pano = MenuItem::with_id(app, "pano", "Geniş görünümü aç", true, None::<&str>)?;
            let cikis = MenuItem::with_id(app, "cikis", "Kalkan'dan çık", true, Some("CmdOrCtrl+Q"))?;
            let ayrac = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(app, &[&durum_ogesi, &ayrac, &ac, &pano, &acilis, &cikis])?;

            let tepsi = TrayIconBuilder::with_id("kalkan")
                .icon(Image::from_bytes(TEPSI)?)
                .icon_as_template(true)
                .tooltip("Kalkan")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, olay| match olay.id.as_ref() {
                    "ac" => panel_goster(app, None),
                    "pano" => pano_ac(app),
                    "acilis" => {
                        let al = app.autolaunch();
                        let _ = if al.is_enabled().unwrap_or(false) { al.disable() } else { al.enable() };
                    }
                    "cikis" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tepsi, olay| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left, button_state: MouseButtonState::Up, rect, ..
                    } = olay
                    {
                        panel_degistir(tepsi.app_handle(), rect);
                    }
                })
                .build(app)?;

            let handle = app.handle().clone();
            std::thread::spawn(move || izleyici(handle, tepsi, durum_ogesi));
            Ok(())
        })
        .on_window_event(|pencere, olay| {
            // Sadece menü çubuğu paneli odak kaybında kapanır; geniş görünüm normal pencere
            let panel_mi = pencere.label() == "panel";
            match olay {
                WindowEvent::Focused(false) if panel_mi => {
                    GIZLENME_MS.store(simdi_ms(), Ordering::Relaxed);
                    let _ = pencere.hide();
                }
                WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    let _ = pencere.hide();
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .expect("Kalkan uygulaması başlatılamadı");
}
