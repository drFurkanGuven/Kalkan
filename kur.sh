#!/bin/zsh
# Kalkan servisini kurar: arka planda sürekli çalışır, açılışta kendiliğinden başlar.
# sudo şifresi sadece bu kurulumda bir kez sorulur.
#
#   ./kur.sh            öğrenme süresi 24 saat (önerilen)
#   ./kur.sh 2h         daha kısa öğrenme (test için; 30m, 2h, 3d gibi)

set -e
cd "$(dirname "$0")"
OGRENME=${1:-24h}

VERI="/Library/Application Support/Kalkan"
LOG="/Library/Logs/Kalkan"
PLIST="/Library/LaunchDaemons/com.kalkan.servis.plist"
ETIKET="com.kalkan.servis"

echo "🛡️  Kalkan kurulumu (öğrenme süresi: $OGRENME)"
echo "→ Derleniyor..."
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
cargo build --release -q -p kalkan -p kalkan-servis

UYGULAMA=""
if command -v npm > /dev/null; then
  echo "→ Mac uygulaması paketleniyor (ilk seferde birkaç dakika sürer)..."
  (cd uygulama && npm install --silent && npx tauri build --bundles app > /dev/null)
  UYGULAMA="target/release/bundle/macos/Kalkan.app"
else
  echo "⚠ npm bulunamadı, menü çubuğu uygulaması atlandı (servis yine kurulur)."
fi

echo "→ Yönetici şifresi gerekiyor (sadece bu kurulumda)."
sudo -v

# Eski kurulum varsa durdur ve tam boşalmasını bekle (bootout/bootstrap yarışını önle)
sudo launchctl bootout system/$ETIKET 2>/dev/null || true
for i in 1 2 3 4 5 6 7 8; do
  sudo launchctl print system/$ETIKET >/dev/null 2>&1 || break
  sleep 1
done

sudo mkdir -p "$VERI/bin" "$LOG"
sudo install -m 755 target/release/kalkan-servis "$VERI/bin/kalkan-servis"
sudo install -m 755 target/release/kalkan "$VERI/bin/kalkan"
sudo mkdir -p /usr/local/bin
sudo ln -sf "$VERI/bin/kalkan" /usr/local/bin/kalkan
# Cihaz üreticileri için IEEE OUI listesi (varsa; tazelemek için: ./oui_guncelle.sh)
[[ -f veri/oui.csv ]] && sudo install -m 644 veri/oui.csv "$VERI/oui.csv"
# Bilinen zafiyet listesi (CISA KEV; tazelemek için: ./zafiyet_guncelle.sh)
[[ -f veri/kev.json ]] && sudo install -m 644 veri/kev.json "$VERI/kev.json"

sudo tee "$PLIST" > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$ETIKET</string>
  <key>ProgramArguments</key>
  <array>
    <string>$VERI/bin/kalkan-servis</string>
    <string>--ogrenme-suresi</string><string>$OGRENME</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>5</integer>
  <key>StandardErrorPath</key><string>$LOG/servis.log</string>
  <key>StandardOutPath</key><string>$LOG/servis.log</string>
</dict>
</plist>
EOF
sudo chmod 644 "$PLIST"

# Metin logunu döndür: 1 MB'ı geçince yenisine geç, 5 eski dosyayı bzip2 ile sakla (macOS newsyslog)
# N: sürece sinyal gönderme (launchd dosyayı yeniden açar)
echo "$LOG/servis.log  644  5  1024  *  NJ" | sudo tee /etc/newsyslog.d/com.kalkan.servis.conf > /dev/null

# Yükle; başlamazsa birkaç kez dene, sonra kickstart ile zorla
sudo launchctl enable system/$ETIKET 2>/dev/null || true
for i in 1 2 3 4 5; do
  sudo launchctl bootstrap system "$PLIST" 2>/dev/null || true
  sudo launchctl print system/$ETIKET >/dev/null 2>&1 && break
  sleep 1
done
sudo launchctl kickstart -k system/$ETIKET 2>/dev/null || true

# Soket hazır olana kadar bekle (ilk açılışta liste yükleme sürebilir)
for i in {1..40}; do
  [[ -S "$VERI/kalkan.sock" ]] && break
  sleep 0.5
done

if [[ -n "$UYGULAMA" && -d "$UYGULAMA" ]]; then
  osascript -e 'quit app "Kalkan"' 2>/dev/null || true
  rm -rf /Applications/Kalkan.app 2>/dev/null || sudo rm -rf /Applications/Kalkan.app
  cp -R "$UYGULAMA" /Applications/ 2>/dev/null || sudo cp -R "$UYGULAMA" /Applications/
  open /Applications/Kalkan.app
  echo "→ Kalkan uygulaması /Applications'a kuruldu, menü çubuğunda kalkan simgesi görünecek."
fi

echo
echo "✅ Kurulum tamam. Servis arka planda çalışıyor ve açılışta kendiliğinden başlayacak."
echo
kalkan durum || true
echo
echo "Durum:   kalkan durum"
echo "Günlük:  kalkan gunluk            (CSV: kalkan gunluk --saat 720 --csv > gunluk.csv)"
echo "Log:     tail -f $LOG/servis.log"
echo "Kaldır:  ./kaldir.sh"
