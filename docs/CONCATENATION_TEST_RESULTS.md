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
