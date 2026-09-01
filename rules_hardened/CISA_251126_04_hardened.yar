rule CISA_251126_04_HARDENED : trojan hides_artifacts
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        source_report = "MAR-251126.r1.v1"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar25-261a"
        original_rule = "rules/CISA_MAR-251126_IvantiEPMM.yar"
        description = "Hardened version of CISA_251126_04: adds nocase to 2 text strings. Detects malicious jar Tomcat listener shell samples"
        hardening_note = "$s0,$s1 are plain Java package/class paths, given nocase. $s2-$s7 are binary checksums/hashes, unchanged."

    strings:
        $s0 = "com/mobileiron/service/" nocase
        $s1 = "WebAndroidAppInstaller.class" nocase
        $s2 = { 5A 5D BB 33 C0 43 31 B0 2D DC 58 F2 75 44 CE E5 }
        $s3 = { 97 DC AC 0F A7 69 97 A4 5A 72 E8 96 AC 43 9E 01 }
        $s4 = { E0 E0 7E 40 F3 F8 87 30 C5 83 30 C5 43 14 E7 67 }
        $s5 = { DB E6 F7 F9 BD FC BE 75 00 BF 6F B3 59 B7 28 07 }
        $s6 = { C6 BF A4 1D 28 AB 7A B9 3E 09 B1 D8 E2 FA 09 36 }
        $s7 = { B8 0E 8E 0B 97 2D AE CF B4 B8 6E CD E5 E6 BA 92 }

    condition:
        all of them
}
