rule CISA_10450442_01_HARDENED : LEMURLOOT webshell communicates_with_c2 remote_access
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        family = "LEMURLOOT"
        source_report = "AA23-158A"
        source_url = "https://www.cisa.gov/sites/default/files/2023-07/aa23-158a-stopransomware-cl0p-ransomware-gang-exploits-moveit-vulnerability_8.pdf"
        original_rule = "rules/CISA_10450442_LEMURLOOT_MOVEit.yar"
        description = "Hardened version of CISA_10450442_01: adds nocase to all strings (all plain text). Detects ASPX webshell samples"
        hardening_note = "All 5 strings are plain text (product names, SQL/cloud identifiers, ASPX header, custom HTTP header prefix). All given nocase."

    strings:
        $s1 = "MOVEit.DMZ" nocase
        $s2 = "%@ Page Language=" nocase
        $s3 = "MySQL" nocase
        $s4 = "Azure" nocase
        $s5 = "X-siLock-" nocase

    condition:
        all of them
}
