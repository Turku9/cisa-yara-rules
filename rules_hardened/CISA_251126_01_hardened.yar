rule CISA_251126_01_HARDENED : trojan hides_artifacts
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        source_report = "MAR-251126.r1.v1"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar25-261a"
        original_rule = "rules/CISA_MAR-251126_IvantiEPMM.yar"
        description = "Hardened version of CISA_251126_01: adds nocase to 2 text strings. Detects malicious jar filter samples"
        hardening_note = "$s0,$s1 are plain Java package/class paths, given nocase. $s2-$s7 are binary checksums/hashes (Java class constant pool data), unchanged."

    strings:
        $s0 = "org/apache/http/client" nocase
        $s1 = "/wo/ReflectUtil.class" nocase
        $s2 = { 83 2E 9D 42 02 A3 81 42 02 B3 C7 57 34 C4 A8 21 }
        $s3 = { 8C 8E C0 B6 14 0E 92 08 89 EE EB 1A 11 7D F4 4E }
        $s4 = { 5B 97 FF F6 12 C9 16 F5 17 C8 5B 5F 44 0E 07 30 }
        $s5 = { A9 21 59 ED 8E 7A 28 D6 29 FA E3 D0 4C 3D 0F CE }
        $s6 = { 5A BD F7 24 E8 66 5F 07 2F 7C 0C 0E A9 E3 8D C5 }
        $s7 = { 05 1B AE 97 B1 88 FF 01 16 EF 3F 44 9E 5F 43 AE }

    condition:
        all of them
}
