rule GRXBA_HARDENED
{
    meta:
        description = "Hardened version of GRXBA: adds nocase to all strings (all plain English help text and identifiers). Detects the infostealer GRXBA version 1.1.3.0"
        date = "2025-01"
        filetype = "pe"
        maltype = "infostealer"
        author = "CISA / FBI / ASD's ACSC (hardened by cisa-yara-rules project)"
        source_report = "AA23-352A"
        source_url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"
        original_rule = "rules/CISA_AA23-352A_PlayRansomware_GRXBA.yar"
        hardening_note = "Added nocase to all 8 strings - all are plain text identifiers or help messages."

    strings:
        $GRB_NET_hex = "GRB_NET" nocase
        $GRB_NET_exe_hex = "GRB_NET.exe" nocase
        $Copyright_Zabbix_2023_hex = "Copyright Zabbix 2023" nocase
        $GRB_NT_hex = "GRB_NT" nocase
        $help_string_1_hex = "HelpText+File.txt/127.0.0.1-127.0.0.255/127.0.0.1-24" nocase
        $help_string_2_hex = "HelpText^Domain name for Users and Computers gathering. If not set will be used domain of current user" nocase
        $help_string_3_hex = "HelpTextbGRB mode. scan/scanall/clr. scan - network scanner. scanall - grab all.  clr - event logs cleaner" nocase
        $help_string_4_hex = "HelpText:Input: f/r/s. f - file, r - range, s - subnet, d - domain" nocase

    condition:
        7 of them
}
