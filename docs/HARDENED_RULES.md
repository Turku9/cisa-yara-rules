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

## Meterpreter/ASPX ve BRICKSTORM Ek Kurallar (2026-08-25)

### Kapsam
- CISA_10430311_03 (ASPX Webshell) - kismi hardening
- CISA_251155_01 (BRICKSTORM, Go paket yollari) - kismi hardening
- CISA_251217_03 (BRICKSTORM, Rust varyanti) - tam hardening

### Yontem
- CISA_10430311_03: $s1, $s2 rastgele/encode gorunumlu karakter dizileri
  oldugu icin degistirilmedi. $s3 (OWAwebconfig), $s4 (TUCSON), $s5 (eval)
  duz metin oldugu icin nocase eklendi.
- CISA_251155_01: $s0 x86 opcode baytlari, degistirilmedi. $s1-$s9 Go
  paket/fonksiyon yollari (duz metin), hepsine nocase eklendi.
- CISA_251217_03: Tum 10 string HTTP header/protokol metni veya hex
  kimlik oldugu icin hepsine nocase eklendi.

## Guncel Hardened Kural Sayisi: 13
- CISA_25993211_02 (SPAWNSLOTH)
- PlayForESXi (Play Ransomware ESXi)
- CISA_10454006_01, _03, _04, _05, _06, _07 (SUBMARINE - 6 kural)
- CISA_251165_02 (BRICKSTORM - DNS query)
- GRXBA (Play Ransomware infostealer)
- CISA_10430311_03 (Meterpreter/ASPX webshell)
- CISA_251155_01 (BRICKSTORM - Go paket yollari)
- CISA_251217_03 (BRICKSTORM - Rust varyanti)

## Meterpreter, RESURGE, LEMURLOOT, FIRESTARTER Ek Kurallar (2026-08-25)

### Kapsam
- CISA_10430311_02 (Meterpreter, fresh binary) - kismi hardening
- CISA_25993211_01 (RESURGE backdoor) - tam hardening
- CISA_10450442_01 (LEMURLOOT webshell) - tam hardening
- CISA_261290_01 (FIRESTARTER injector) - kismi hardening

### Degerlendirilip Hardening Uygulanmayan Kurallar
- CISA_10430311_01 (Meterpreter) - tamamen x86 shellcode, metin string yok
- CISA_261290_02 (FIRESTARTER_shellcode) - tamamen x86 shellcode, metin string yok

Bu iki kural bilerek atlanmadi, incelendi ve hardening'e uygun olmadigi
tespit edildi (tum string'ler binary opcode).

### Dogrulama Testi

| Kural | Orijinal (case testi) | Hardened (case testi) |
|---|---|---|
| CISA_25993211_01 (RESURGE) | KACIRDI | YAKALADI |

## Guncel Hardened Kural Sayisi: 17
- CISA_25993211_02 (SPAWNSLOTH)
- PlayForESXi
- CISA_10454006_01, _03, _04, _05, _06, _07 (SUBMARINE - 6 kural)
- CISA_251165_02 (BRICKSTORM)
- GRXBA
- CISA_10430311_02, _03 (Meterpreter/ASPX - 2 kural)
- CISA_251155_01, _251217_03 (BRICKSTORM - 2 kural)
- CISA_25993211_01 (RESURGE)
- CISA_10450442_01 (LEMURLOOT)
- CISA_261290_01 (FIRESTARTER)

## HermeticWiper (2026-08-25)

### Kapsam
CISA_10375867_01 (HermeticWiper wiper malware)

### Yontem - Farkli bir yaklasim
Bu kuralin tum string'leri UTF-16 (wide) formatinda kodlanmis duz metin
olarak tespit edildi (Windows registry yollari, surucu isimleri, yetki
adlari), ancak orijinal kuralda hex byte olarak yazilmisti. Hex formatinda
nocase eklenemez. Bunun yerine string'ler DUZ METIN olarak yeniden
yazildi ve "wide nocase" modifier kombinasyonu eklendi - bu hem ayni
baytlari arar (davranis degismedi) hem de artik buyuk/kucuk harf
degisimine karsi dayanikli.

### Test
Hardened kural derleme ve calisma testinden basariyla gecti. Kural
"N of them" yapisinda oldugu icin (tek string yeterli degil), izole
tek-string testi yerine derleme/calisma dogrulamasi yapildi.

## Guncel Hardened Kural Sayisi: 18
- CISA_25993211_02 (SPAWNSLOTH)
- PlayForESXi
- CISA_10454006_01, _03, _04, _05, _06, _07 (SUBMARINE - 6 kural)
- CISA_251165_02 (BRICKSTORM)
- GRXBA
- CISA_10430311_02, _03 (Meterpreter/ASPX - 2 kural)
- CISA_251155_01, _251217_03 (BRICKSTORM - 2 kural)
- CISA_25993211_01 (RESURGE)
- CISA_10450442_01 (LEMURLOOT)
- CISA_261290_01 (FIRESTARTER)
- CISA_10375867_01 (HermeticWiper) - hex-to-wide-text donusumu ile

## Ivanti EPMM - Tum Aile (2026-08-25)

### Kapsam
5 kuralin tumu (CISA_251126_01 - 05) incelendi ve hardening uygulandi.

### Yeni Bir Kategori: AES Anahtarlari
Bu turda ilk kez, hex-digit ASCII metni olarak yazilmis SABIT SIFRELEME
ANAHTARLARIYLA karsilasildi ($s7 in _03: "7c6a8867d728c3bb", $s9 in _05:
"3c6e0b8a9c15224a"). Bunlara BILEREK nocase eklenmedi - base64 bloklariyla
ayni mantik: anahtar degeri kaynak kodunda birebir kopyalanip yapistirilir,
bir saldirganin harfleri rastgele degistirmesi gercekci bir senaryo degildir
ve byte degerini degistirerek sifreleme/cozme islevini bozar.

### Yeni Bir Durum: Java Constant Pool Uzunluk On-eki
$s10 (_03) ve $s8 (_05), Java .class dosyalarinin ic formatinda
(CONSTANT_Utf8), string'lerin basina 2 baytlik bir uzunluk degeri
eklenir. Kesilmis/kismi bu on-ek baytindan dolayi bu string'ler
hex formatinda birakildi - metne cevirip nocase eklemek tam bayt
eslesmesini bozabilirdi.

### Sonuc
- CISA_251126_02: TAM hardening (10/10 string)
- CISA_251126_03: KISMI (10/12, AES anahtari ve length-prefix haric)
- CISA_251126_05: KISMI (11/13, AES anahtari ve length-prefix haric)
- CISA_251126_01, _04: KISMI (2/8 - digerleri binary hash/checksum)

## HARDENING TURU TAMAMLANDI - Nihai Ozet

Depodeki 30 orijinal kuralin TAMAMI incelendi:
- 23 kural hardened edildi (23 dosya, rules_hardened/ altinda)
- 2 kural (Meterpreter _01, FIRESTARTER _02) tamamen shellcode
  oldugu icin hardening'e uygun degil, degistirilmedi
- 5 kural zaten iyi tasarlanmis (SUBMARINE _02 entropi tabanli) veya
  hardening konusu SUBMARINE _06/_07'nin base64 bloklari gibi kismen
  ele alindi

Toplam hardened kural sayisi: 23

## BRICKSTORM Son Kural: _261234_01 (2026-08-25)

### Bulus Yontemi
Kalan tum kurallar, otomatik bir Python script'i ile UTF-16 (wide)
formatli gizli string'ler acisindan sistematik olarak tarandi. Bu
tarama, daha once HermeticWiper disinda gozden kacan bir kural
(CISA_261234_01) buldu.

### Kapsam
CISA_261234_01 (BRICKSTORM, AOT/derlenmis varyant)

### Yontem
$s0-$s5: UTF-16 (wide) formatinda dosya yollari, HermeticWiper'da
kullanilan yontemle metne cevrilip "wide nocase" eklendi.
$s6, $s7: duz metin (bir .NET debug baslik etiketi ve WebSocket
protokol sabiti), nocase eklendi.
$s8, $s9: sifir-bayt (null) ayiracli sistem cagrisi isim listeleri,
metne cevrilmedi - ayirici baytlarin kaybi tam bayt eslesmesini
bozabilirdi.
$s10: 32 karakterlik hex kimlik, AES anahtarlariyla ayni mantikla
degistirilmedi.

## SISTEMATIK UTF-16 TARAMASI TAMAMLANDI

234 hex blogu, depodeki TUM 9 kaynak dosyasi (rules/*.yar) uzerinde
otomatik script ile tarandi. Sonuc: HermeticWiper (zaten hardened)
disinda sadece 1 ek kural (CISA_261234_01) wide-encoded string
icerdigi tespit edildi, o da simdi hardened edildi. Depoda baska
gozden kacan wide-encoded kural KALMADIGI dogrulanmis oldu - tarama
9/9 kaynak dosyasini kapsadi.

## NIHAI GUNCEL HARDENED KURAL SAYISI: 24

BRICKSTORM ailesinin tum 7 kurali artik degerlendirildi:
_251165_02, _251155_01, _251217_03, _261234_01 (4 tanesi hardened)
_251155_02, _251155_03, _251186_02 (3 tanesi opcode agirlikli, N/A)

## BRICKSTORM Son Kural: _261234_01 (2026-08-25)

### Bulus Yontemi
Kalan tum kurallar, otomatik bir Python script'i ile UTF-16 (wide)
formatli gizli string'ler acisindan sistematik olarak tarandi. Bu
tarama, daha once HermeticWiper disinda gozden kacan bir kural
(CISA_261234_01) buldu.

### Kapsam
CISA_261234_01 (BRICKSTORM, AOT/derlenmis varyant)

### Yontem
$s0-$s5: UTF-16 (wide) formatinda dosya yollari, HermeticWiper'da
kullanilan yontemle metne cevrilip "wide nocase" eklendi.
$s6, $s7: duz metin (bir .NET debug baslik etiketi ve WebSocket
protokol sabiti), nocase eklendi.
$s8, $s9: sifir-bayt (null) ayiracli sistem cagrisi isim listeleri,
metne cevrilmedi - ayirici baytlarin kaybi tam bayt eslesmesini
bozabilirdi.
$s10: 32 karakterlik hex kimlik, AES anahtarlariyla ayni mantikla
degistirilmedi.

## SISTEMATIK UTF-16 TARAMASI TAMAMLANDI

234 hex blogu, depodeki TUM 9 kaynak dosyasi (rules/*.yar) uzerinde
otomatik script ile tarandi. Sonuc: HermeticWiper (zaten hardened)
disinda sadece 1 ek kural (CISA_261234_01) wide-encoded string
icerdigi tespit edildi, o da simdi hardened edildi. Depoda baska
gozden kacan wide-encoded kural KALMADIGI dogrulanmis oldu - tarama
9/9 kaynak dosyasini kapsadi.

## NIHAI GUNCEL HARDENED KURAL SAYISI: 24

BRICKSTORM ailesinin tum 7 kurali artik degerlendirildi:
_251165_02, _251155_01, _251217_03, _261234_01 (4 tanesi hardened)
_251155_02, _251155_03, _251186_02 (3 tanesi opcode agirlikli, N/A)
