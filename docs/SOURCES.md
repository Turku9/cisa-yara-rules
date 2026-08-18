# Kaynak Takibi

Bu depodaki her kural, CISA tarafından yayınlanmış resmi bir Malware
Analysis Report (MAR) veya Cybersecurity Advisory (CSA) belgesinden
elle çıkarılmıştır. Asağıdaki tablo hangi kuralın hangi rapordan
geldiğini gösterir.

| Rapor No | Yayın/Güncelleme Tarihi | Konu | Platform | Kural Sayısı | Dosya |
|---|---|---|---|---|---|
| MAR-10430311.c1.v1 | 2023-09-07 | Meterpreter + ASPX Webshell | Windows PE / ASPX | 3 | rules/CISA_10430311_Meterpreter_ASPXWebshell.yar |
| MAR-25993211.r1.v1 | 2025-03-28 | RESURGE + SPAWNSLOTH (Ivanti Connect Secure) | Linux ELF | 2 | rules/CISA_25993211_RESURGE_SPAWNSLOTH.yar |
| AA23-352A | 2025-06-04 (guncelleme) | Play Ransomware (ESXi) + GRXBA infostealer | Linux ELF / Windows PE | 2 | rules/CISA_AA23-352A_PlayRansomware_GRXBA.yar |

## Kaynak URL
- MAR-10430311.c1.v1: https://www.cisa.gov/sites/default/files/2023-09/MAR-10430311.c1.v1.CLEAR_.pdf
- MAR-25993211.r1.v1: https://www.cisa.gov/sites/default/files/2025-03/MAR-25993211.r1.v1.CLEAR_.pdf
- AA23-352A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a

## Notlar
- CISA'nin kendi raporlari arasinda metadata alan isimlendirmesinde
  tutarsizlik var (ornegin "Capabilities" ile "capabilities" farkli
  raporlarda farkli büyük/kucuk harfle geçiyor). Kurallar orijinal
  kaynaga sadik kalinarak degistirilmeden aktarilmistir.
- AA23-352A raporunda ayrica Suricata (ag imzasi) kurallari da
  bulunmaktaydi; bu depo sadece YARA formatindaki kurallari icerir,
  Suricata kurallari kapsam disi birakilmistir.
- AA23-352A raporundaki $PLAY_ext_str kuralinda kaynak sayfada
  "fullword?" seklinde bir yazim hatasi tespit edildi, "fullword"
  olarak duzeltildi (YARA'da gecerli bir modifier olmadigi icin).

## Lisans notu
CISA raporlari TLP:CLEAR olarak yayinlanir ve "Subject to standard
copyright rules, TLP:CLEAR information may be shared without
restriction" ifadesiyle serbestce paylasilabilir statudedir. ABD federal
hukumet eseri olmasi nedeniyle kamu mali (public domain) kabul edilir.
