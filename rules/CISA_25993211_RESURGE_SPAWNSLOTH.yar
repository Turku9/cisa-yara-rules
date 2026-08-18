rule CISA_25993211_01 : RESURGE backdoor dropper rootkit bootkit
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "25993211"
        date = "2025-03-03"
        last_modified = "20250303_1446"
        actor = "n/a"
        family = "SPAWN"
        capabilities = "n/a"
        malware_type = "backdoor dropper rootkit bootkit"
        tool_type = "unknown"
        description = "Detects RESURGE malware samples"
        sha256_1 = "52bbc44eb451cb5e16bf98bc5b1823d2f47a18d71f14543b460395a1c1b1aeda"
        source_report = "MAR-25993211.r1.v1"
        source_url = "https://www.cisa.gov/sites/default/files/2025-03/MAR-25993211.r1.v1.CLEAR_.pdf"

    strings:
        $s1 = "snprintf"
        $s2 = "CGI::param"
        $s3 = "coreboot.img"
        $s4 = "scanner.py"
        $s5 = { 6C 6F 67 73 }
        $s6 = "accept"
        $s7 = "strncpy"
        $s8 = "dsmdm"
        $s9 = "funchook_create"
        $s10 = { 20 83 B8 ED }

    condition:
        all of them
}

rule CISA_25993211_02 : SPAWNSLOTH trojan compromises_data_integrity
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "25993211"
        date = "2025-03-04"
        last_modified = "20250304_0906"
        actor = "n/a"
        family = "SPAWN"
        capabilities = "compromises-data-integrity"
        malware_type = "trojan"
        tool_type = "unknown"
        description = "Detects SPAWNSLOTH malware samples"
        sha256_1 = "3526af9189533470bc0e90d54bafb0db7bda784be82a372ce112e361f7c7b104"
        source_report = "MAR-25993211.r1.v1"
        source_url = "https://www.cisa.gov/sites/default/files/2025-03/MAR-25993211.r1.v1.CLEAR_.pdf"

    strings:
        $s1 = "dslogserver"
        $s2 = "g_do_syslog_servers_exist"
        $s3 = "_ZN5DSLog4File3addEPKci"
        $s4 = "dlsym"

    condition:
        all of them
}
