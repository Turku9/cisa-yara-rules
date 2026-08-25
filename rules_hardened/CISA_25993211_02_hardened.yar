rule CISA_25993211_02_HARDENED : SPAWNSLOTH trojan compromises_data_integrity
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "25993211"
        date = "2025-09-15"
        last_modified = "20250916_1511"
        actor = "n/a"
        family = "SPAWN"
        capabilities = "compromises-data-integrity"
        malware_type = "trojan"
        tool_type = "unknown"
        description = "Hardened version of CISA_25993211_02: adds nocase to resist case-swap evasion. Detects Go-Based SPAWNSLOTH malware samples"
        sha256_1 = "3526af9189533470bc0e90d54bafb0db7bda784be82a372ce112e361f7c7b104"
        source_report = "MAR-25993211.r1.v1"
        source_url = "https://www.cisa.gov/sites/default/files/2025-03/MAR-25993211.r1.v1.CLEAR_.pdf"
        original_rule = "rules/CISA_25993211_RESURGE_SPAWNSLOTH.yar"
        hardening_note = "Added nocase modifier to all strings. No other changes to detection logic."

    strings:
        $s1 = "dslogserver" nocase
        $s2 = "g_do_syslog_servers_exist" nocase
        $s3 = "_ZN5DSLog4File3addEPKci" nocase
        $s4 = "dlsym" nocase

    condition:
        all of them
}
