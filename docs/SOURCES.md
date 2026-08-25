# Kaynak Takibi

Bu depodaki her kural, CISA tarafından yayınlanmış resmi bir Malware
Analysis Report (MAR) veya Cybersecurity Advisory (CSA) belgesinden
elle çıkarılmıştır. Asağıdaki tablo hangi kuralın hangi rapordan
geldiğini gösterir.

| Rapor No | Yayın/Guncelleme Tarihi | Konu | Platform | Kural Sayisi | Dosya |
|---|---|---|---|---|---|
| MAR-10430311.c1.v1 | 2023-09-07 | Meterpreter + ASPX Webshell | Windows PE / ASPX | 3 | rules/CISA_10430311_Meterpreter_ASPXWebshell.yar |
| MAR-25993211.r1.v1 | 2025-03-28 | RESURGE + SPAWNSLOTH (Ivanti Connect Secure) | Linux ELF | 2 | rules/CISA_25993211_RESURGE_SPAWNSLOTH.yar |
| AA23-352A | 2025-06-04 (guncelleme) | Play Ransomware (ESXi) + GRXBA infostealer | Linux ELF / Windows PE | 2 | rules/CISA_AA23-352A_PlayRansomware_GRXBA.yar |
| AR25-338A | 2026-02-11 (son guncelleme) | BRICKSTORM backdoor (PRC devlet destekli, VMware/Windows) | Linux ELF (Go/Rust/.NET AOT) | 7 | rules/CISA_AR25-338A_BRICKSTORM.yar |

## Kaynak URL
- MAR-10430311.c1.v1: https://www.cisa.gov/sites/default/files/2023-09/MAR-10430311.c1.v1.CLEAR_.pdf
- MAR-25993211.r1.v1: https://www.cisa.gov/sites/default/files/2025-03/MAR-25993211.r1.v1.CLEAR_.pdf
- AA23-352A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a
- AR25-338A: https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF

## Notlar
- CISA'nin kendi raporlari arasinda metadata alan isimlendirmesinde
  tutarsizlik var (ornegin "Capabilities" ile "capabilities" farkli
  raporlarda farkli büyük/kucuk harfle geçiyor). Kurallar orijinal
  kaynaga sadik kalinarak degistirilmemistir.
- AA23-352A raporunda ayrica Suricata (ag imzasi), AR25-338A raporunda
  ayrica Sigma (SIEM) kurallari da bulunmaktaydi; bu depo sadece YARA
  formatindaki kurallari icerir, digerleri kapsam disi birakilmistir.
- AA23-352A raporundaki $PLAY_ext_str kuralinda kaynak sayfada
  "fullword?" seklinde bir yazim hatasi tespit edildi, "fullword"
  olarak duzeltildi.
- AR25-338A raporundaki CISA_251155_02 kuralinda kaynak PDF'de sha256_1
  alani 4 kez tekrar tanimlanmisti (CISA'nin kendi hatasi); YARA ayni
  meta anahtarinin tekrarina izin vermedigi icin sha256_1/_2/_3/_4
  olarak ayristirildi.
- AR25-338A, PRC (Cin) devlet destekli bir APT grubuna ait, en guncel
  (2026-02-11) ve en yuksek kural sayisina (7) sahip kaynagimizdir.

## Lisans notu
CISA raporlari TLP:CLEAR olarak yayinlanir ve "Subject to standard
copyright rules, TLP:CLEAR information may be shared without
restriction" ifadesiyle serbestce paylasilabilir statudedir. ABD federal
hukumet eseri olmasi nedeniyle kamu mali (public domain) kabul edilir.

## Guncelleme - 5. Kaynak

| Rapor No | Yayin/Guncelleme Tarihi | Konu | Platform | Kural Sayisi | Dosya |
|---|---|---|---|---|---|
| AA23-158A | 2023-06-07 | LEMURLOOT webshell (CL0P / MOVEit Transfer istismari) | ASPX / Windows | 1 | rules/CISA_10450442_LEMURLOOT_MOVEit.yar |

Kaynak URL: https://www.cisa.gov/sites/default/files/2023-07/aa23-158a-stopransomware-cl0p-ransomware-gang-exploits-moveit-vulnerability_8.pdf

## Guncelleme - 6. Kaynak

| Rapor No | Yayin/Guncelleme Tarihi | Konu | Platform | Kural Sayisi | Dosya |
|---|---|---|---|---|---|
| MAR-261290.r1.v1 (AR26-113A) | 2026-04-19 | FIRESTARTER backdoor (Cisco Firepower/ASA, UAT-4356/ArcaneDoor APT) | Linux ELF (Cisco firmware) | 2 | rules/CISA_MAR-261290_FIRESTARTER.yar |

Kaynak URL: https://www.cisa.gov/news-events/analysis-reports/ar26-113a

Not: Bu kaynak STIX 2.1 formatinda elde edilmistir, PDF degil. Kaynak
metinde kucuk bir yazim hatasi (tool_type = "unknownk") ve YARA'da
gecersiz string isimlendirmesi ($1, $2) tespit edildi, sirasiyla
"unknown" ve $s1/$s2 olarak duzeltildi. Bu kaynakta sha256 hash
bilgisi paylasilmamis, kaynaga sadik kalinarak eklenmedi.
