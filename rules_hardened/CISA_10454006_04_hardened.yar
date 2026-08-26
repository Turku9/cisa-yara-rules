rule CISA_10454006_04_HARDENED : SUBMARINE trojan backdoor hides_artifacts hides_executing_code infects_files installs_other_components remote_access exploitation
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "10454006"
        date = "2023-07-05"
        family = "SUBMARINE"
        description = "Hardened version of CISA_10454006_04: adds nocase to all strings. Detects SUBMARINE launcher script samples"
        sha256_1 = "b98f8989e8706380f779bfd464f3dea87c122651a7a6d06a994d9a4758e12e43"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"
        original_rule = "rules/CISA_10454006_SUBMARINE_Barracuda.yar"
        hardening_note = "Added nocase to all 7 strings."

    strings:
        $s1 = "sleep" nocase
        $s2 = "|base64 -d" nocase
        $s3 = "LD_PRELOAD" nocase
        $s4 = "/home/product/code/firmware/current/sbin/smtpctl restart" nocase
        $s5 = "echo -n '" nocase
        $s6 = "sh" nocase
        $s7 = "#! /bin/sh" nocase

    condition:
        filesize < 2KB and 6 of them
}
