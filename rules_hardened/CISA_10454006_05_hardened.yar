rule CISA_10454006_05_HARDENED : SUBMARINE trojan backdoor remote_access_trojan compromises_data_integrity cleans_traces_of_infection hides_artifacts installs_other_components remote_access exploitation
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "10454006"
        date = "2023-07-05"
        family = "SUBMARINE"
        description = "Hardened version of CISA_10454006_05: adds nocase to all strings. Detects SUBMARINE launcher script samples"
        sha256_1 = "cc131dd1976a47ee3b631a136c3224a138716e9053e04d8bea3ee2e2c5de451a"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"
        original_rule = "rules/CISA_10454006_SUBMARINE_Barracuda.yar"
        hardening_note = "Added nocase to all 7 strings."

    strings:
        $s1 = "LD_PRELOAD" nocase
        $s2 = "#! /bin/sh" nocase
        $s3 = "LD_PRELOAD=/boot/os_tools/libutil.so exec" nocase
        $s4 = ">/dev/null 2>&1" nocase
        $s5 = "bsmtpd control script" nocase
        $s6 = "BSMTPD_PID" nocase
        $s7 = "/reload/restart" nocase

    condition:
        filesize < 6KB and 6 of them
}
