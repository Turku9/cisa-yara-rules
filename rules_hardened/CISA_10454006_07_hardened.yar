rule CISA_10454006_07_HARDENED : SUBMARINE trojan dropper exploit_kit evades_av hides_executing_code hides_artifacts exploitation
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "10454006"
        date = "2023-07-11"
        family = "SUBMARINE"
        description = "Hardened version of CISA_10454006_07: adds nocase to text strings only. Base64 blob ($s3) left unchanged. Detects ESG FileName exploit samples"
        sha256_1 = "8695945155d3a87a5733d31bf0f4c897e133381175e1a3cdc8c73d9e38640239"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"
        original_rule = "rules/CISA_10454006_SUBMARINE_Barracuda.yar"
        hardening_note = "Added nocase to 2 text strings. $s3 is base64 data, left unchanged."

    strings:
        $s1 = "| base64 -d | sh" nocase
        $s2 = "echo -n" nocase
        $s3 = { 59 32 46 30 49 43 39 32 59 58 49 76 64 47 31 77 4c 33 49 67 66 43 42 69 59 58 4e 6c 4e 6a 51 67 4c 57 51 67 4c 57 6b 67 66 43 42 30 59 58 49 67 }

    condition:
        filesize < 1KB and all of them
}
