# Hardened Kurallar - Obfuscation Direnc Iyilestirmesi

## Amac
`docs/OBFUSCATION_TEST_RESULTS.md` testinde tespit edilen case-sensitivity
zayifligini, CISA'nin orijinal kurallarina dokunmadan duzeltmek.

## Yaklasim
`rules/` klasoru CISA'nin orijinal kurallarinin degistirilmemis kopyasi
olarak kalir - kaynak dogrulamasi icin. `rules_hardened/` klasoru ayni
kurallarin iyilestirilmis versiyonlarini icerir. Iki klasor birbirinden
bagimsizdir, orijinal kurallar asla degistirilmez.

## Iyilestirme Yontemi
Metin tabanli string'lere `nocase` modifier'i eklendi. Hex/byte pattern
string'ler (sabit dosya yollari, binary imzalar) degistirilmedi, cunku
bunlar zaten case-sensitivity'den etkilenmiyor.

## Pilot Test - Once/Sonra Kiyaslamasi (2026-08-25)

| Kural | Orijinal (case testi) | Hardened (case testi) |
|---|---|---|
| CISA_25993211_02 (SPAWNSLOTH) | KACIRDI | YAKALADI |

## Kapsam
Su an sadece 2 kural hardened edildi (pilot):
- rules_hardened/CISA_25993211_02_hardened.yar
- rules_hardened/CISA_10454006_06_hardened.yar

Kalan 28 kural henuz hardened edilmedi. Bu, gelecekteki bir asamada
ayni yontemle genisletilebilir.

## Onemli Not
Hardened kurallar UZERETIM ICIN oneri niteligindedir, orijinal kaynagin
yerini almaz. docs/SOURCES.md'deki kaynak takibi sadece rules/ klasorunu
kapsar - rules_hardened/ ayri bir katmandir ve CISA'nin resmi yayinindan
BAGIMSIZ bir gelistirmedir.
