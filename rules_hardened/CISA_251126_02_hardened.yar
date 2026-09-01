rule CISA_251126_02_HARDENED : trojan
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        source_report = "MAR-251126.r1.v1"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar25-261a"
        original_rule = "rules/CISA_MAR-251126_IvantiEPMM.yar"
        description = "Hardened version of CISA_251126_02: adds nocase to all strings (all plain text Java class/method names). Detects malicious servlet filter class loader samples"
        hardening_note = "All 10 strings are plain text Java package paths, class names, and method names. All given nocase."

    strings:
        $s0 = "org/apache/http" nocase
        $s1 = "client/wo/ReflectUtil" nocase
        $s2 = "SecurityHandlerWanListener" nocase
        $s3 = "getListener" nocase
        $s4 = "addListener" nocase
        $s5 = "TomcatEmbeddedContext" nocase
        $s6 = "gzipDecompress" nocase
        $s7 = "getApplicationEventListeners" nocase
        $s8 = "setApplicationEventListeners" nocase
        $s9 = "evilClassName" nocase

    condition:
        all of them
}
