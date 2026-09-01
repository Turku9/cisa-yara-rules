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
