rule CISA_10454006_01_HARDENED : SUBMARINE trojan backdoor remote_access_trojan remote_access information_gathering exploitation determines_c2_server controls_local_machine compromises_data_integrity
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "10452108"
        date = "2023-06-29"
        last_modified = "20230711_1500"
        family = "SUBMARINE"
        description = "Hardened version of CISA_10454006_01: adds nocase to text strings. Opcode string ($s6) left unchanged. Detects SUBMARINE Barracuda backdoor samples"
        sha256_1 = "81cf3b162a4fe1f1b916021ec652ade4a14df808021eeb9f7c81c8d2326bddab"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"
        original_rule = "rules/CISA_10454006_SUBMARINE_Barracuda.yar"
        hardening_note = "Added nocase to 10 text strings. $s6 is x86 opcode bytes, left as-is (case concept does not apply to machine code)."

    strings:
        $s1 = "250-mail2.eccentric.duck" nocase
        $s2 = "openssl aes-256" nocase
        $s3 = "echo -n '%s' | base64 -d" nocase
        $s4 = "-iv" nocase
        $s5 = "Hello %s [%s], pleased to meet you" nocase
        $s6 = { e8 47 fa ff }
        $s7 = "command" nocase
        $s8 = "-iv 69822b6c" nocase
        $s9 = "send" nocase
        $s10 = "socket" nocase
        $s11 = "connect" nocase

    condition:
        filesize < 15KB and 8 of them
}
