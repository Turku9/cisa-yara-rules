#!/usr/bin/env bash
RULES_DIR="rules"
REQUIRED_META=(author date description source_report source_url)
FAIL=0

echo "=== 1. DERLEME TESTI ==="
while IFS= read -r f; do
    if yarac "$f" /dev/null 2>/tmp/err.txt; then
        echo "  [OK]   $f"
    else
        echo "  [FAIL] $f"
        sed 's/^/         /' /tmp/err.txt
        FAIL=1
    fi
done < <(find "$RULES_DIR" -name "*.yar")

echo ""
echo "=== 2. METADATA KONTROLU ==="
while IFS= read -r f; do
    for m in "${REQUIRED_META[@]}"; do
        if ! grep -q "$m\s*=" "$f"; then
            echo "  [EKSIK] $f -> $m"
            FAIL=1
        fi
    done
done < <(find "$RULES_DIR" -name "*.yar")

echo ""
echo "=== 3. KURAL ADI CAKISMASI ==="
DUP=$(grep -rhoP '^\s*(private\s+|global\s+)*rule\s+\K\w+' "$RULES_DIR" | sort | uniq -d)
if [ -n "$DUP" ]; then
    echo "  [CAKISMA] $DUP"
    FAIL=1
else
    echo "  [OK] Cakisma yok"
fi

echo ""
echo "=== 4. ISTATISTIK ==="
echo "  Dosya sayisi : $(find "$RULES_DIR" -name '*.yar' | wc -l)"
echo "  Kural sayisi : $(grep -rhoP '^\s*(private\s+|global\s+)*rule\s+\K\w+' "$RULES_DIR" | wc -l)"

echo ""
[ $FAIL -eq 0 ] && echo "SONUC: GECTI" || echo "SONUC: KALDI"
exit $FAIL
