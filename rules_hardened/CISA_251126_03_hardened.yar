rule CISA_251126_03_HARDENED : trojan installs_other_components exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        source_report = "MAR-251126.r1.v1"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar25-261a"
        original_rule = "rules/CISA_MAR-251126_IvantiEPMM.yar"
        description = "Hardened version of CISA_251126_03: adds nocase to text strings. AES key and Java constant-pool-prefixed string left unchanged. Detects malicious servlet filter class samples"
        hardening_note = "$s7 is a hardcoded AES key spelled as hex-digit text - left unchanged, as recasing would not reflect a realistic evasion (the key value is copy-pasted verbatim in malware source, not manually retyped). $s10 has a leading Java class-file length-prefix byte, kept as hex to preserve exact match. All other 10 strings given nocase."

    strings:
        $s0 = "ServletRequestListener" nocase
        $s1 = "ClassLoader" nocase
        $s2 = "ServletRequestEvent" nocase
        $s3 = "/HttpServletResponse" nocase
        $s4 = "HttpSession" nocase
        $s5 = "HttpServletResponse" nocase
        $s6 = "headerValue" nocase
        $s7 = "7c6a8867d728c3bb"
        $s8 = "pass" nocase
        $s9 = "SecretKeySpec" nocase
        $s10 = { 15 68 74 74 70 73 3A 2F 2F 77 77 77 2E 6C 69 76 65 2E 63 6F 6D 2F }
        $s11 = "Referer" nocase

    condition:
        all of them
}
