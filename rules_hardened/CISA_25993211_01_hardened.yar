rule CISA_25993211_01_HARDENED : RESURGE backdoor dropper rootkit bootkit
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        family = "SPAWN"
        source_report = "MAR-25993211.r1.v1"
        source_url = "https://www.cisa.gov/sites/default/files/2025-03/MAR-25993211.r1.v1.CLEAR_.pdf"
        original_rule = "rules/CISA_25993211_RESURGE_SPAWNSLOTH.yar"
        description = "Hardened version of CISA_25993211_01: adds nocase to all text strings. Detects RESURGE malware samples"
        hardening_note = "$s1-$s4,$s6-$s9 are plain text (function/file names), given nocase. $s10 is opcode bytes, unchanged."

    strings:
        $s1 = "snprintf" nocase
        $s2 = "CGI::param" nocase
        $s3 = "coreboot.img" nocase
        $s4 = "scanner.py" nocase
        $s5 = "logs" nocase
        $s6 = "accept" nocase
        $s7 = "strncpy" nocase
        $s8 = "dsmdm" nocase
        $s9 = "funchook_create" nocase
        $s10 = { 20 83 B8 ED }

    condition:
        all of them
}
