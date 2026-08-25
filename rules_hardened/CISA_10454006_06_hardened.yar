rule CISA_10454006_06_HARDENED : SUBMARINE trojan backdoor cleans_traces_of_infection hides_artifacts installs_other_components
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "10454006"
        date = "2023-07-11"
        last_modified = "20230727_1200"
        actor = "n/a"
        family = "SUBMARINE"
        capabilities = "cleans-traces-of-infection hides-artifacts installs-other-components"
        malware_type = "trojan backdoor"
        tool_type = "unknown"
        description = "Hardened version of CISA_10454006_06: adds nocase to resist case-swap evasion. Detects SUBMARINE SQL trigger samples"
        sha256_1 = "2a353e9c250e5ea905fa59d33faeaaa197d17b4a4785456133aab5dbc1d1d5d5"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"
        original_rule = "rules/CISA_10454006_SUBMARINE_Barracuda.yar"
        hardening_note = "Added nocase modifier to text-representable strings. Byte-level hex strings kept as-is."

    strings:
        $s1 = { 54 52 49 47 47 45 52 }
        $s2 = { 43 52 45 41 54 45 }
        $s3 = "SELECT \"echo -n" nocase
        $s4 = { 62 61 73 65 36 34 20 2d 64 20 7c 20 73 68 }
        $s5 = "root" nocase
        $s6 = "SET" nocase
        $s7 = "END IF;" nocase
        $s8 = { 48 34 73 49 41 41 41 41 41 41 41 41 41 2b 30 61 43 33 42 55 }
        $s9 = { 2f 76 61 72 2f 74 6d 70 2f 72 }
        $s10 = { 2f 72 6f 6f 74 2f 6d 61 63 68 69 6e 65 }

    condition:
        filesize < 250KB and all of them
}
