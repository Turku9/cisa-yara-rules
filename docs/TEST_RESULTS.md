# Test Sonuclari

## FP (False Positive) Testi #1 - Temiz Korpus Taramasi

**Tarih:** 2026-08-18
**Test edilen kural sayisi:** 5 (2 kaynak dosya, 2 CISA MAR raporu)
**Yontem:** Kali Linux sisteminde bulunan bilinen-temiz ELF binary,
metin ve PHP dosyalarina karsi tum kural setini tarama.

### Korpus Icerigi

| Kategori | Kaynak | Dosya Sayisi |
|---|---|---|
| ELF binary | /usr/bin, /usr/lib, /usr/sbin | ~500 |
| Metin dosyasi | /usr/share/doc | ~100 |
| PHP dosyasi | /usr/share, /var/www | ~77 |
| **Toplam** | | **677** |

### Sonuc

Sifir eslesme. Test edilen 5 kuralin hicbiri temiz korpusta
tetiklenmedi.

### Yorum

- Bu sonuc beklenen bir sonuctur: kurallarin 4'u spesifik byte-pattern
  (hex) imzalarina dayanmaktadir (Meterpreter, RESURGE), bu tur
  desenlerin rastgele sistem dosyalarinda tesadufen bulunma ihtimali
  dusuktur.
- SPAWNSLOTH kurali (CISA_25993211_02) string tabanli olmasina ragmen
  spesifik sembol adlari kullanir (dslogserver, g_do_syslog_servers_exist),
  jenerik string kullanmadigi icin FP riski dusuktur.
- **Sinirlama:** 677 dosyalik korpus, kurumsal olcekte (milyonlarca
  dosya) karsilasilabilecek cesitliligi temsil etmez. Ozellikle .jar,
  .docx, .zip gibi konteyner formatlari ve genis capli Windows dosya
  sistemi bu testte yer almamistir.
- **Yapilmayan test:** True Positive (TP) dogrulamasi - kurallarin
  gercekten hedef malware'i (Meterpreter, RESURGE, SPAWNSLOTH, ASPX
  webshell) yakalayip yakalamadigi, gercek ornek olmadigi icin bu
  asamada test edilmemistir. CISA'nin verdigi SHA256 hash'leri
  uzerinden VirusTotal gibi platformlarda dogrulama ileride
  yapilabilir.

### Sonraki Adimlar

- [ ] Korpusu .jar / .docx / .zip formatlariyla genislet
- [ ] Windows ortaminda (varsa) PE dosyalarina karsi test et
- [ ] Obfuscation testi: pozitif ornek dosyalarinin (varsa) base64/
      sikistirilmis versiyonlarinda kurallarin davranisini olc
- [ ] TP dogrulamasi icin hash-only karsilastirma (VirusTotal API)

## FP (False Positive) Testi #2 - Genisletilmis Kural Seti (7 Kural)

**Tarih:** 2026-08-18
**Test edilen kural sayisi:** 7 (3 kaynak dosya, 3 CISA raporu)
**Korpus:** Ayni 677 dosyalik temiz korpus (Test #1 ile ayni)

### Sonuc

Sifir gercek eslesme. Ancak 167 performans uyarisi tespit edildi:

| Kural | Uyari Sayisi | Sebep |
|---|---|---|
| CISA_10430311_01 | 166 | $s1 stringi (8 bayt hex) YARA tarafindan "cok genel" olarak isaretlendi |
| PlayForESXi | 1 | $base64_encoded_24_byte_val regex deseni yavas tarama uretiyor |

### Yorum

- Performans uyarisi FP degildir - kural yanlis alarm uretmiyor,
  ancak tarama motorunun kisa/genel bir deseni her dosyada aramak
  zorunda kalmasi kaynak tuketimine yol acar.
- Bu, CISA_10430311_01 kuralinin $s1 stringinin ("49 be 77 73 32 5f
  33 32" - 8 bayt) tek basina yeterince ayirt edici olmadigini,
  ancak kuralin "all of them" sarti sayesinde (8 stringin hepsi
  gerekli) nihai sonucun hala guvenilir kaldigini gosteriyor.
- **Oneri:** Buyuk olcekli/kurumsal taramalarda performans onemliyse,
  bu tur genel stringler icin YARA'nin "private" rule ozelligi veya
  koşullu on-filtreleme (once daha ayirt edici bir string arayip,
  bulunursa diger stringlere bakma) degerlendirilebilir. Bu depoda
  kurallar CISA kaynagina sadik kalinarak degistirilmemistir; bu not
  gelecekteki bir optimizasyon calismasi icin kayit altina alinmistir.

### Guncellenmis Toplam

- Kaynak sayisi: 3
- Kural sayisi: 7
- FP: 0/677
- Performans uyarisi: 167 (esas olarak 1 kuraldan kaynaklanan bilinen durum)
