rule CISA_10430311_03_HARDENED : ASPX_WEBSHELL webshell
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        source_report = "MAR-10430311.c1.v1"
        source_url = "https://www.cisa.gov/sites/default/files/2023-09/MAR-10430311.c1.v1.CLEAR_.pdf"
        original_rule = "rules/CISA_10430311_Meterpreter_ASPXWebshell.yar"
        description = "Hardened version of CISA_10430311_03: adds nocase to plain-text strings only. Random-looking encoded strings ($s1, $s2) left unchanged."
        hardening_note = "$s1 and $s2 appear to be base64-like random data, not given nocase. $s3-$s5 are plain text (OWAwebconfig, TUCSON, eval), given nocase."

    strings:
        $s1 = { 5a 30 32 6a 77 36 43 36 63 55 }
        $s2 = { 5a 38 49 30 32 38 33 6e 77 38 }
        $s3 = "OWAwebconfig" nocase
        $s4 = "TUCSON" nocase
        $s5 = "eval" nocase

    condition:
        3 of them
}
