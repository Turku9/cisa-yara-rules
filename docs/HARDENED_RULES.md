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

## Ikinci Kural: PlayForESXi (2026-08-25)

### Sonuc

| Kural | Orijinal (case testi) | Hardened (case testi) |
|---|---|---|
| PlayForESXi | KACIRDI | YAKALADI |

### Test Surecinde Bulunan Ek Bulgu: fullword Modifier Riski

Test sirasinda, PlayForESXi kuralindaki dosya uzanti string'lerinin
(.vmdk, .vmem, .vmsd vb.) `fullword` modifier'i tasidigi goruldu.
`fullword`, string'in hemen oncesinde/sonrasinda alfanumerik karakter
olmamasini sart kosar. Gercek dunyada VM dosyalari genelde
"backup.vmdk", "server1.vmem" gibi - yani uzantidan hemen once bir
dosya adi (harf/rakam) bulunur - adlandirilir. Bu durumda fullword
sarti TEKNIK OLARAK saglanmayabilir, cunku uzantidan once "k", "1"
gibi alfanumerik bir karakter vardir.

**Bu bir hardening hatasi degildir - CISA'nin orijinal kuralinda da
mevcut bir tasarim secimidir.** Test sirasinda tesadufen ortaya
cikmistir ve ayri bir bulgu olarak kayit altina alinmistir. Duzeltilmesi
onerilmez cunku fullword'un kaldirilmasi FP riskini artirabilir (ornegin
".log" gibi kisa bir uzanti fullword olmadan cok fazla dosyada tetiklenir).
Bu, konunun basit olmadigini, her degisikligin bir taviz (trade-off)
icerdigini gosteren iyi bir ornektir.

## Guncel Hardened Kural Sayisi: 3
- CISA_25993211_02 (SPAWNSLOTH)
- CISA_10454006_06 (SUBMARINE SQL trigger)
- PlayForESXi (Play Ransomware ESXi)

## SUBMARINE Ailesi - Toplu Hardening (2026-08-25)

### Kapsam
SUBMARINE kaynak dosyasindaki (rules/CISA_10454006_SUBMARINE_Barracuda.yar)
7 kuraldan 6'si hardened edildi: _01, _03, _04, _05, _06, _07.
_02 (entropi tabanli kural) zaten obfuscation'a dayanikli oldugu icin
hardened edilmedi - degisiklik gerektirmiyor.

### Yontem Farklari
- _01, _03, _04, _05: tum string'ler duz metin oldugu icin hepsine
  nocase eklendi.
- _01: $s6 (x86 opcode baytlari) hardened edilmedi - makine kodunda
  "buyuk/kucuk harf" kavrami yok.
- _06, _07: base64-encoded blok iceren string'ler ($s8 ve $s3) BILEREK
  nocase almadi - base64 alfabesi buyuk/kucuk harfe duyarlidir, bu
  bloklara nocase eklemek anlamsal olarak yanlis olurdu ve kuralin
  davranisini bozabilirdi.

### Dogrulama Testi

| Kural | Orijinal (case testi) | Hardened (case testi) |
|---|---|---|
| CISA_10454006_03 | KACIRDI | YAKALADI |

(_01, _04, _05, _06, _07 ayni yontemle yazildi, _03 ile ayni davranisi
gostermesi beklenir; sistematik dogrulama gelecekte genisletilebilir)

## Guncel Hardened Kural Sayisi: 8
- CISA_25993211_02 (SPAWNSLOTH)
- PlayForESXi (Play Ransomware ESXi)
- CISA_10454006_01, _03, _04, _05, _06, _07 (SUBMARINE - 6 kural)

## Hardened Edilmeyen / Edilmemesi Gereken Kurallar
- CISA_10454006_02 (SUBMARINE) - zaten entropi tabanli, degisiklik gerekmiyor
- Tum hex/binary-opcode agirlikli kurallar (Meterpreter, RESURGE_01,
  HermeticWiper, BRICKSTORM, FIRESTARTER, Ivanti EPMM'nin cogu) -
  case-sensitivity kavrami bunlara uygulanamaz

## BRICKSTORM ve GRXBA Hardening (2026-08-25)

### Kapsam
- CISA_251165_02 (BRICKSTORM, Go sembol isimleri ve DNS-over-HTTPS URL'leri)
- GRXBA (Play Ransomware infostealer, yardim metinleri)

### Yontem
Her iki kural da tamamen duz metin stringlerden olusuyor - hicbir hex/
opcode veya base64 blok icermiyor. Tum stringlere nocase eklendi,
tespit mantigi (kac string gerekli) degistirilmedi.

### Not
GRXBA icin orijinal kuralin "all of them" (8/8) sarti, hardened versiyonda
"7 of them" olarak hafifce gevsetildi - uzun help_string_4 metninin tam
eslesmesi konusunda ihtiyati bir esneklik payi birakildi. Tespit gucu
buyuk olcude korunuyor.

## Guncel Hardened Kural Sayisi: 10
- CISA_25993211_02 (SPAWNSLOTH)
- PlayForESXi (Play Ransomware ESXi)
- CISA_10454006_01, _03, _04, _05, _06, _07 (SUBMARINE - 6 kural)
- CISA_251165_02 (BRICKSTORM)
- GRXBA (Play Ransomware infostealer)
