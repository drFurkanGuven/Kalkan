#!/bin/zsh
# IEEE'nin MAC üretici listesini (OUI) indirir; cihaz listesinde "Apple", "Samsung" gibi
# üretici adları için kullanılır. Liste ayda bir güncellenir; birkaç ayda bir çalıştırmak yeter.
# Sonra ./kur.sh ile kurulu servise kopyalanır.
set -e
cd "$(dirname "$0")"
mkdir -p veri
gecici=$(mktemp)
curl -fsSL -m 120 -A "Mozilla/5.0 (Macintosh)" -o "$gecici" https://standards-oui.ieee.org/oui/oui.csv
# Bozuk ya da yarım indirmeyi kurulu listenin üstüne yazma
if [[ $(head -1 "$gecici") == Registry,Assignment,* ]] && (( $(wc -l < "$gecici") > 30000 )); then
  mv "$gecici" veri/oui.csv
  echo "✅ Üretici listesi güncellendi: $(($(wc -l < veri/oui.csv) - 1)) kayıt. Kurulu servise geçirmek için: ./kur.sh"
else
  rm -f "$gecici"
  echo "❌ İndirilen dosya beklenen biçimde değil, eski liste korundu." >&2
  exit 1
fi
