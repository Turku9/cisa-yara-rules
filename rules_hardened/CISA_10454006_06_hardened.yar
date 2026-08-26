rule CISA_10454006_06_HARDENED_V2 : SUBMARINE trojan backdoor cleans_traces_of_infection hides_artifacts installs_other_components
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "10454006"
        date = "2023-07-11"
        family = "SUBMARINE"
        description = "Hardened v2 of CISA_10454006_06: adds nocase to text strings only. Base64 blob ($s8) left unchanged - base64 is case-sensitive by design. Detects SUBMARINE SQL trigger samples"
        sha256_1 = "2a353e9c250e5ea905fa59d33faeaaa197d17b4a4785456133aab5dbc1d1d5d5"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"
        original_rule = "rules/CISA_10454006_SUBMARINE_Barracuda.yar"
        hardening_note = "Added nocase to 9 text strings. $s8 is a base64-encoded blob and was NOT given nocase - base64 alphabet is case-sensitive, adding nocase would be semantically incorrect."

    strings:
        $s1 = "TRIGGER" nocase
        $s2 = "CREATE" nocase
        $s3 = "SELECT \"echo -n" nocase
        $s4 = "base64 -d | sh" nocase
        $s5 = "root" nocase
        $s6 = "SET" nocase
        $s7 = "END IF;" nocase
        $s8 = { 48 34 73 49 41 41 41 41 41 41 41 41 41 2b 30 61 43 33 42 55 }
        $s9 = "/var/tmp/r" nocase
        $s10 = "/root/machine" nocase

    condition:
        filesize < 250KB and all of them
}
