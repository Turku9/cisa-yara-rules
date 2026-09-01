rule CISA_10430311_02_HARDENED : METERPRETER controls_local_machine compromises_data_integrity communicates_with_c2 keylogger exploit_kit remote_access_trojan backdoor downloader screen_capture virus remote_access exploitation network_capture
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        source_report = "MAR-10430311.c1.v1"
        source_url = "https://www.cisa.gov/sites/default/files/2023-09/MAR-10430311.c1.v1.CLEAR_.pdf"
        original_rule = "rules/CISA_10430311_Meterpreter_ASPXWebshell.yar"
        description = "Hardened version of CISA_10430311_02: adds nocase to the one text string. Detects Fresh Meterpreter binary samples"
        hardening_note = "Only $s5 (PAYLOAD:) is plain text, given nocase. All other strings are x86 opcode bytes, unchanged."

    strings:
        $s0 = { 58 a4 53 e5 }
        $s1 = { 02 d9 c8 5f }
        $s2 = { 99 a5 74 61 }
        $s3 = { 4c 77 26 07 }
        $s4 = { 29 80 6b 00 }
        $s5 = "PAYLOAD:" nocase
        $s6 = { 48 83 ec 28 49 c7 c1 40 }

    condition:
        all of them
}
