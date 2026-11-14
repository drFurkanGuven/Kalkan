#!/bin/zsh
# Kalkan servisini durdurur ve kaldırır.
#
#   ./kaldir.sh            servisi kaldır, öğrenilen model ve geçmiş kalsın
#   ./kaldir.sh --hepsi    model, veritabanı ve loglar dahil her şeyi sil

VERI="/Library/Application Support/Kalkan"
ETIKET="com.kalkan.servis"

echo "→ Yönetici şifresi gerekiyor."
sudo -v || exit 1
sudo launchctl bootout system/$ETIKET 2>/dev/null && echo "→ Servis durduruldu."
sudo rm -f /Library/LaunchDaemons/$ETIKET.plist /usr/local/bin/kalkan /etc/newsyslog.d/com.kalkan.servis.conf
sudo rm -rf "$VERI/bin"

# Menü çubuğu uygulaması ve oturum açılışı kaydı
osascript -e 'quit app "Kalkan"' 2>/dev/null
rm -f "$HOME/Library/LaunchAgents/Kalkan.plist"
[[ -d /Applications/Kalkan.app ]] && { rm -rf /Applications/Kalkan.app 2>/dev/null || sudo rm -rf /Applications/Kalkan.app; } && echo "→ Uygulama kaldırıldı."

if [[ "$1" == "--hepsi" ]]; then
  sudo rm -rf "$VERI" /Library/Logs/Kalkan
  echo "✅ Kalkan ve tüm verileri silindi."
else
  echo "✅ Kalkan kaldırıldı. Model ve geçmiş şurada duruyor: $VERI"
  echo "   Tamamen silmek için: ./kaldir.sh --hepsi"
fi
