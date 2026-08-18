# Konteyner Format Testi - Bulgular

## Test Amaci
Bu depodaki YARA kurallarinin, ZIP tabanli konteyner formatlarinda
(.zip, .jar, .docx, .xlsx vb.) tespit yapip yapamadigini dogrulamak.

## Metodoloji
1. Bilinen bir kuralin aradigi string ("dslogserver") iceren duz bir
   metin dosyasi olusturuldu.
2. Ayni icerik, standart zip araciyla bir .zip arsivine sikistirildi.
3. Basit tek-stringli bir demo kural her iki dosyaya karsi calistirildi.

## Sonuc

| Dosya Turu | Tarama Sonucu |
|---|---|
| Duz metin dosyasi | ESLESTI |
| Ayni icerik, ZIP icinde | ESLESMEDI (sessizce kacirildi) |

## Neden Oluyor
ZIP (ve dolayisiyla JAR, DOCX, XLSX, PPTX gibi turevleri) icerigi
deflate algoritmasiyla sikistirir. Sikistirilmis baytlar, orijinal
metnin baytlariyla ortusmez. YARA varsayilan olarak dosyanin ham
baytlarini okur; sikistirilmis veriyi ac(a)madigi icin arama
sessizce basarisiz olur - hata vermez, sadece hicbir sey bulamaz.

## Operasyonel Risk
Bu depodaki hicbir kural, su an .jar/.docx/.xlsx/.zip formatlarinin
ICINE bakamaz. Bir saldirgan, tespit edilen bir payload'i sadece bir
ZIP arsivine koyarak, mevcut kural setinin tamamini atlatabilir. Bu,
gercek dunyada yaygin kullanilan bir kacis teknigidir (email eklerinde
.zip/.docx kullanimi, arsiv icine gizleme).

## Onerilen Cozumler (Sonraki Asama)

1. **On-isleme (unpacking) katmani:** Tarama hattina, ZIP/JAR/Office
   dosyalarini tarama oncesi acan bir on-isleme adimi eklenmeli. Ornegin
   Python'da zipfile modulu ile icerigi cikarip, cikan dosyalari ayrica
   YARA'ya vermek.
2. **YARA'nin kendi modul destegi:** YARA'nin bazi surumlerinde 'zip'
   modulu bulunur (derleme ayarina bagli). Bu, dosya iceriklerini acmadan
   metadata seviyesinde inceleme saglar ama tam icerik taramasi icin
   yeterli degildir.
3. **Konteyner-farkinda kural yazimi:** Yeni CISA kurallari eklenirken,
   hedef dosya turu .jar/.docx ise, kural aciklamasina bu sinirlama not
   dusulmeli ve mumkunse on-isleme gerekliligi metadata'ya eklenmeli.

## Durum
Bu bulgu 2026-08-18 tarihinde tespit edilmistir. Depo su an icin bu
sinirlamayi COZMEMEKTEDIR - sadece belgelemektedir. Uretim entegrasyonu
oncesi bu katmanin eklenmesi ONERILIR.

## Cozum: scan_with_extraction.sh

Bu depoya `tools/scan_with_extraction.sh` script'i eklenmistir. Bu
script, hedef dosya bir ZIP/JAR/DOCX/XLSX/PPTX oldugunda, taramadan
once icerigi otomatik olarak acar, sonra hem ham dosyayi hem acilan
icerigi ayri ayri tarar.

### Dogrulama Testi (2026-08-18)

Demo kural (`dslogserver` stringini arayan tek-stringli test kurali)
kullanilarak asagidaki kanit elde edildi:

| Adim | Sonuc |
|---|---|
| 1. Ham ZIP dosyasi taranir | Eslesme YOK (kor nokta dogrulandi) |
| 2. ZIP icerigi acilir | Basarili |
| 3. Acilan icerik taranir | Eslesme VAR (sorun cozuldu) |

### Kullanim

./tools/scan_with_extraction.sh <hedef_dosya.zip>

### Bilinen Sinirlamalar
- Su an sadece .zip, .jar, .docx, .xlsx, .pptx uzantilarini taniyor
  (hepsi ayni ZIP tabanli format oldugu icin ayni unzip komutuyla
  acilabiliyor).
- Ic ice gecmis arsivleri (zip icinde zip) su an tek seviye aciyor,
  recursive degil. Ileride gerekirse eklenebilir.
- .rar, .7z gibi ZIP-disi arsiv formatlari desteklenmiyor.
