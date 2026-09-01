rule CISA_251126_05_HARDENED : trojan installs_other_components exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        source_report = "MAR-251126.r1.v1"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar25-261a"
        original_rule = "rules/CISA_MAR-251126_IvantiEPMM.yar"
        description = "Hardened version of CISA_251126_05: adds nocase to text strings. AES key and Java constant-pool-prefixed string left unchanged. Detects malicious Tomcat listener shell class samples"
        hardening_note = "$s9 is a hardcoded AES key (hex-digit text), left unchanged. $s8 has a leading Java class-file length-prefix byte, kept as hex. All other 11 strings given nocase."

    strings:
        $s0 = "ClassLoader" nocase
        $s1 = "mobileiron/service" nocase
        $s2 = "WebAndroidAppInstaller" nocase
        $s3 = "addListener" nocase
        $s4 = "servletRequestListenerClass" nocase
        $s5 = "addApplicationEventListenerMethod" nocase
        $s6 = "base64Decode" nocase
        $s7 = "contentType" nocase
        $s8 = { 08 72 65 73 70 6F 6E 73 65 }
        $s9 = "3c6e0b8a9c15224a"
        $s10 = "kpasslogin" nocase
        $s11 = "ServletRequestListener" nocase
        $s12 = "SecretKeySpec" nocase

    condition:
        all of them
}
