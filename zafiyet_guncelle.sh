#!/bin/zsh
# CISA KEV (aktif sömürülen açıklar) listesini indirir. Tarama, okuduğu servis
# sürümlerini bu listeyle karşılaştırıp "bu üründe aktif sömürülen açık var" uyarısı verir.
# CISA listeyi sık günceller; haftada/ayda bir çalıştırmak iyi olur.
# Sonra ./kur.sh ile kurulu servise geçer.
set -e
cd "$(dirname "$0")"
mkdir -p veri
gecici=$(mktemp)
echo "→ CISA KEV indiriliyor..."
curl -fsSL -m 120 -o "$gecici" https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# Geçerli JSON ve beklenen alan var mı?
if command -v python3 > /dev/null; then
  if ! python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['vulnerabilities'] and d['catalogVersion']" "$gecici" 2>/dev/null; then
    rm -f "$gecici"; echo "❌ İndirilen dosya beklenen biçimde değil, eski liste korundu." >&2; exit 1
  fi
fi
mv "$gecici" veri/kev.json
if command -v python3 > /dev/null; then
  n=$(python3 -c "import json; print(len(json.load(open('veri/kev.json'))['vulnerabilities']))")
  s=$(python3 -c "import json; print(json.load(open('veri/kev.json'))['catalogVersion'])")
  echo "✅ Zafiyet listesi güncellendi (CISA KEV $s): $n aktif sömürülen açık. Kurulu servise geçirmek için: ./kur.sh"
else
  echo "✅ Zafiyet listesi güncellendi. Kurulu servise geçirmek için: ./kur.sh"
fi
