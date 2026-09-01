# String Parcalama (Concatenation) Testi - Sonuclar

## Amac
Kurallarin, saldirganlarin kaynak kodunda string'leri parcalayarak
(ornegin "My" & "SQL" seklinde, calisma aninda birlesecek sekilde)
tespiti atlatip atlatamayacagini olcmek. Bu, case-sensitivity testinden
FARKLI bir atlatma teknigidir ve nocase ile cozulmez.

## Metodoloji
LEMURLOOT kuralinin aradigi "MySQL" kelimesi, bir test dosyasinda
kasitli olarak "My" ve "SQL" seklinde ayri parcalara bolundu (VBScript
tarzi birlestirme operatoru kullanilarak). Hem orijinal hem hardened
kural bu dosyaya karsi test edildi.

## Sonuc

| Test | Orijinal Kural | Hardened Kural |
|---|---|---|
| Kontrol (bitisik "MySQL") | ESLESTI | (test edilmedi, orijinal zaten dogrulandi) |
| Parcalanmis ("My" & "SQL") | KACIRDI | KACIRDI |

## Kritik Bulgu

**Hardened katmanimiz (nocase eklenmis kurallar) bu atlatma teknigine
karsi hicbir koruma SAGLAMIYOR.** nocase sadece buyuk/kucuk harf
farkina bakmama sagliyor; string'in fiziksel olarak parcalara
bolunmesi FARKLI bir sorun ve mevcut hardening yontemimizle
COZULEMIYOR.

## Neden Onemli
Bu teknik ozellikle yorumlanan (derlenmeyen) dillerde - PHP, VBScript,
JavaScript, PowerShell - gercek dunyada yaygin kullanilir, cunku kod
kaynak seviyesinde okunabilir metin olarak kalir ve saldirgan onu
istedigi sekilde bolebilir. LEMURLOOT (ASPX) gibi kaynak-kodu-tabanli
kurallarimiz bu acidan risk altindadir. Derlenmis binary kurallarda
(Meterpreter, BRICKSTORM opcode kisimlari gibi) bu teknik uygulanamaz,
cunku derleyici zaten string'leri tek parca halinde diziye yazar.

## Bu Depo Icin Kapsam Notu
Bu bulgu, mevcut hardening katmaninin (rules_hardened/) SINIRINI
gosterir: "hardened" etiketi sadece case-sensitivity'e karsi
dayaniklilik anlamina gelir, TUM atlatma tekniklerine karsi
baglisiklik anlamina GELMEZ. Bu ayrimin raporlarda ve ilgili
taraflara aktarimda acikca belirtilmesi onemlidir.

## Olasi Cozum (Uygulanmadi)
YARA'nin regex ozelligi ile "My.{0,20}SQL" gibi esnek bir arama
yapilabilir, ama bu FP riskini ciddi olcude artirir (cok fazla
yanlis eslesme uretebilir) ve orijinal kaynaga sadik kalma
prensibimizle celisir. Bu depo kapsaminda bu cozum UYGULANMAMISTIR,
sadece bir gelecek arastirma notu olarak kayit altina alinmistir.

## Ek Test: Bosluk/Ayirici Sokma (2026-08-25)

### Metodoloji
SPAWNSLOTH hardened kuralinin aradigi "dslogserver" kelimesinin
ortasina bir bosluk, "dlsym" kelimesinin ortasina bir TAB karakteri
sokularak test edildi.

### Sonuc

| Test | Hardened Kural |
|---|---|
| Kontrol (degistirilmemis) | ESLESTI |
| Kelime ortasina bosluk/tab sokulmus | KACIRDI |

### ONEMLI KISITLAMA - Bu Bulgunun Gercekci Uygulanabilirligi
Bu test, YARA'nin teorik bir davranisini olcer - bir saldirganin bunu
GERCEKTEN uygulayip uygulayamayacagi, hedef dosya turune baglidir:

- **Kaynak kod tabanli tehditlerde (ASPX, PHP, JS, PowerShell,
  VBScript gibi yorumlanan diller) bu GERCEK bir risktir.** Saldirgan
  "My" & "SQL" gibi calisma-aninda-birlestirme operatorleri kullanarak,
  programin islevselligini bozmadan tespit kuralini atlatabilir. LEMURLOOT
  (ASPX webshell) buna acik bir ornektir.

- **Derlenmis binary dosyalarda (EXE, ELF, .class) bu teknik GENELDE
  UYGULANAMAZ.** Bu tur dosyalardaki string'ler (fonksiyon isimleri,
  sabit metinler) programin calisma mantiginin bir parcasidir; bu
  string'in ortasina bosluk/tab sokmak, saldirganin kendi zararli
  yazilimini da bozar (fonksiyon cagirisi basarisiz olur, program
  hata verir veya coker). SPAWNSLOTH testimiz teknik olarak dogru
  bir YARA davranisini gosteriyor, ancak bu senaryo gercek bir
  saldirganin uygulayabilecegi bir atlatma yontemi DEGILDIR.

### Sonuc - Risk Onceligi
Bu bulgunun operasyonel onemi, kaynak koduna dayali kurallarimizda
(LEMURLOOT, SUBMARINE'in launcher script kurallari, GRXBA'nin help
text'leri gibi) YUKSEK, derlenmis binary kurallarinda (Meterpreter,
BRICKSTORM opcode kisimlari, RESURGE gibi) DUSUK/GECERSIZDIR.

## Genisletme: SUBMARINE Shell Script Kurallarinda Dogrulama (2026-08-25)

### Metodoloji
LEMURLOOT'ta (ASPX kaynak kod) bulunan string parcalama riskinin,
depodaki DIGER kaynak-kodu-tabanli kurallarda da gecerli olup
olmadigi test edildi. SUBMARINE'in shell script kurallarindan biri
(CISA_10454006_03) secildi, cunku bu da derlenmis binary degil,
CALISAN kaynak koddur (#!/bin/sh betikleri).

"base64 -d" komutu, shell degiskenleri kullanilarak parcalandi:
    b="base"; c="64 -d"; echo $b$c |sh
Bu, gercek bir shell script'te CALISAN, gecerli bir komut birlestirme
teknigidir - saldirganin bunu gercekte kullanabilecegi kanitlanmis
bir yontemdir (LEMURLOOT'taki VBScript "&" operatorunden farkli ama
ayni mantik: kaynak kod calisma aninda birlesir, islevsellik korunur).

### Sonuc

| Test | Hardened Kural |
|---|---|
| Kontrol (bitisik "base64 -d") | ESLESTI |
| Shell degiskeniyle parcalanmis | KACIRDI |

### Dogrulanmis Kapsam
String parcalama riski, su an ITIBARIYLE ASAGIDAKI kaynak-kodu-tabanli
kurallarda GECERLI ve DOGRULANMIS kabul edilmelidir:
- LEMURLOOT (CISA_10450442_01) - ASPX, dogrulandi
- SUBMARINE launcher/SQL kurallari (CISA_10454006_03/04/05/06/07) -
  shell script/SQL, _03 uzerinde dogrulandi, digerleri ayni formatta
  oldugu icin ayni riski tasidigi varsayilmalidir (sistematik tek tek
  test edilmedi)

Bu risk, derlenmis binary kurallarda (Meterpreter, BRICKSTORM opcode
kisimlari, FIRESTARTER, HermeticWiper, Ivanti EPMM .class dosyalari,
RESURGE) GECERSIZDIR - derleyici string'leri programin veri bolumune
sabit olarak yazar, calisma aninda "birlestirme" soz konusu degildir.

## Encoding Testi: URL-Encode (2026-08-25)

### Metodoloji
LEMURLOOT kuralinin aradigi "MySQL" kelimesi, URL-encode formatina
cevrilerek test edildi (%4d%79%53%51%4c). ASP/ASPX ortaminda
Server.UrlDecode() gibi yerlesik fonksiyonlarla bu format calisma
aninda cozulup gercek kelimeye donusturulebilir - programin islevi
bozulmaz.

### Sonuc

| Test | Hardened Kural |
|---|---|
| Kontrol (duz "MySQL") | ESLESTI |
| URL-encode edilmis | KACIRDI |

### Yorum
Bu, string parcalama bulgumuzla ayni kategoride: kaynak-kodu-tabanli
kurallarda (ASPX, shell script, SQL) GECERLI bir risk. Saldirgan,
programin calisma mantigini bozmadan, kod icindeki hassas kelimeleri
URL-encode, base64 veya benzeri bir formatta gizleyip, calisma
aninda cozebilir.

## NIHAI OZET - Kaynak-Kodu-Tabanli Kurallarda Dogrulanmis Riskler

Su ana kadar LEMURLOOT ve SUBMARINE uzerinde dogrulanan atlatma
teknikleri (tumu ayni kok nedene dayanir: YARA statik/ham bayt
aramasi yapar, kaynak kodun CALISMA ANINDA donusumunu goremez):

1. Buyuk/kucuk harf degisimi - nocase ile COZULDU (23/30 kural hardened)
2. String parcalama (& operatoru, shell degiskenleri) - COZULEMEDI
3. URL-encoding - COZULEMEDI

2 ve 3 numarali riskler, mevcut hardening yontemimizin (nocase modifier)
kapsami DISINDADIR. Cozum icin ya on-isleme/normalizasyon katmani
(kod calistirilmadan once decode/birlestirme islemlerini simule eden
bir analiz araci) ya da davranissal/dinamik analiz gerekir - ikisi de
bu depo kapsaminda uygulanmamistir, ileriki bir asama icin oneri
olarak kayit altina alinmistir.
