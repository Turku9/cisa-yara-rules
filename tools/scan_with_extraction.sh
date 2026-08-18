#!/usr/bin/env bash
# ZIP/JAR/DOCX/XLSX gibi konteyner dosyalarini once acar, sonra tarar.
# Kullanim: ./scan_with_extraction.sh <hedef_dosya>

set -e

TARGET="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="$SCRIPT_DIR/../rules"
TMP_EXTRACT="/tmp/yara_extract_$$"
ALL_RULES="/tmp/all_rules_scan_$$.yar"

if [ -z "$TARGET" ]; then
    echo "Kullanim: $0 <dosya>"
    exit 1
fi

find "$RULES_DIR" -name "*.yar" -printf 'include "%p"\n' > "$ALL_RULES"

echo "=== 1. NORMAL TARAMA (ham dosya, arsiv icini goremez) ==="
yara -r "$ALL_RULES" "$TARGET" || true

echo ""
echo "=== 2. ARSIV ACILIYOR ==="
mkdir -p "$TMP_EXTRACT"
case "$TARGET" in
    *.zip|*.jar|*.docx|*.xlsx|*.pptx)
        unzip -o -q "$TARGET" -d "$TMP_EXTRACT"
        echo "Acildi: $TMP_EXTRACT"
        ;;
    *)
        echo "Bu bir arsiv degil, atlaniyor."
        ;;
esac

echo ""
echo "=== 3. ACILAN ICERIK TARANIYOR ==="
if [ "$(ls -A "$TMP_EXTRACT" 2>/dev/null)" ]; then
    yara -r "$ALL_RULES" "$TMP_EXTRACT" || true
else
    echo "Acilacak icerik yok."
fi

rm -rf "$TMP_EXTRACT" "$ALL_RULES"
