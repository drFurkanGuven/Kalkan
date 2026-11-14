#!/bin/zsh
# Çift tıklanan macOS kurulum paketi (.pkg) üretir. Son kullanıcı terminale girmeden,
# yerleşik Yükleyici penceresiyle kurar; yönetici şifresi kendi penceresinde sorulur.
#
#   ./paket_yap.sh
#
# Sonuç: Kalkan-Kurulum.pkg  →  kullanıcı çift tıklar, "İleri → Kur" der.
# (İmzasız paket: ilk açılışta sağ tık → Aç gerekebilir. İmza/noter için yıllık
#  99$ Apple Developer hesabı gerekir — yol haritası Faz 6.)
set -e
export COPYFILE_DISABLE=1  # macOS ._ meta dosyaları pakete girmesin
cd "$(dirname "$0")"

SURUM="0.1.0"
ETIKET="com.kalkan.servis"
VERI="/Library/Application Support/Kalkan"
LOG="/Library/Logs/Kalkan"
CIKTI="Kalkan-Kurulum.pkg"

echo "🛡️  Kalkan kurulum paketi hazırlanıyor (sürüm $SURUM)"

# 1) Derle (motor + uygulama)
echo "→ Derleniyor..."
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
cargo build --release -q -p kalkan -p kalkan-servis
echo "→ Mac uygulaması paketleniyor..."
(cd uygulama && npm install --silent && npx tauri build --bundles app > /dev/null)

UYGULAMA="target/release/bundle/macos/Kalkan.app"
[[ -d "$UYGULAMA" ]] || { echo "❌ Kalkan.app bulunamadı"; exit 1; }

# 2) Paket içeriğini (kurulduğunda nereye gidecekse) bir ağaçta topla
KOK=$(mktemp -d)
BETIK=$(mktemp -d)
trap 'rm -rf "$KOK" "$BETIK"' EXIT

mkdir -p "$KOK$VERI/bin" "$KOK/Applications"
install -m 755 target/release/kalkan-servis "$KOK$VERI/bin/kalkan-servis"
install -m 755 target/release/kalkan "$KOK$VERI/bin/kalkan"
[[ -f veri/oui.csv ]] && install -m 644 veri/oui.csv "$KOK$VERI/oui.csv"
[[ -f veri/kev.json ]] && install -m 644 veri/kev.json "$KOK$VERI/kev.json"
cp -R "$UYGULAMA" "$KOK/Applications/Kalkan.app"

# 3) postinstall: servisi kur, launchd'ye yükle, log döndürmeyi ayarla, uygulamayı aç
cat > "$BETIK/postinstall" <<POST
#!/bin/zsh
VERI="$VERI"; LOG="$LOG"; ETIKET="$ETIKET"
PLIST="/Library/LaunchDaemons/\$ETIKET.plist"
mkdir -p "\$LOG"
ln -sf "\$VERI/bin/kalkan" /usr/local/bin/kalkan 2>/dev/null || { mkdir -p /usr/local/bin && ln -sf "\$VERI/bin/kalkan" /usr/local/bin/kalkan; }

cat > "\$PLIST" <<PLISTSON
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>\$ETIKET</string>
  <key>ProgramArguments</key>
  <array>
    <string>\$VERI/bin/kalkan-servis</string>
    <string>--ogrenme-suresi</string><string>24h</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>5</integer>
  <key>StandardErrorPath</key><string>\$LOG/servis.log</string>
  <key>StandardOutPath</key><string>\$LOG/servis.log</string>
</dict>
</plist>
PLISTSON
chmod 644 "\$PLIST"

# Log döndürme (1 MB, 5 sıkıştırılmış eski dosya)
echo "\$LOG/servis.log  644  5  1024  *  NJ" > /etc/newsyslog.d/com.kalkan.servis.conf

# Eski sürüm varsa durdur, tam boşalmasını bekle (bootout/bootstrap yarışını önle)
launchctl bootout system/\$ETIKET 2>/dev/null || true
for i in 1 2 3 4 5 6 7 8; do
  launchctl print system/\$ETIKET >/dev/null 2>&1 || break
  sleep 1
done

# Yükle; başlamazsa birkaç kez dene, sonra kickstart ile zorla
launchctl enable system/\$ETIKET 2>/dev/null || true
for i in 1 2 3 4 5; do
  launchctl bootstrap system "\$PLIST" 2>/dev/null || true
  launchctl print system/\$ETIKET >/dev/null 2>&1 && break
  sleep 1
done
launchctl kickstart -k system/\$ETIKET 2>/dev/null || true

# Soket hazır olana kadar kısa bekle (ilk açılışta liste yükleme sürebilir)
for i in \$(seq 1 20); do
  [[ -S "\$VERI/kalkan.sock" ]] && break
  sleep 0.5
done

# Menü çubuğu uygulamasını kuran kullanıcı için aç
KULLANICI=\$(stat -f "%Su" /dev/console)
[[ -n "\$KULLANICI" && "\$KULLANICI" != "root" ]] && launchctl asuser \$(id -u "\$KULLANICI") open -a /Applications/Kalkan.app 2>/dev/null || true
exit 0
POST
chmod +x "$BETIK/postinstall"

# 4) Paketi üret
pkgbuild \
  --root "$KOK" \
  --scripts "$BETIK" \
  --identifier com.kalkan.kurulum \
  --version "$SURUM" \
  --install-location / \
  "$CIKTI"

echo
echo "✅ Hazır: $CIKTI"
echo "   Kullanıcı bu dosyaya çift tıklar, Yükleyici açılır, şifresini girer."
echo "   İmzasız olduğu için ilk açılışta sağ tık → Aç gerekebilir."
