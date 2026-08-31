rule CISA_251165_02_HARDENED : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "251165"
        date = "2025-09-29"
        family = "BRICKSTORM"
        description = "Hardened version of CISA_251165_02: adds nocase to all strings (Go symbol names and DNS URLs, all plain text). Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "aaf5569c8e349c15028bc3fac09eb982efb06eabac955b705a6d447263658e38"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"
        original_rule = "rules/CISA_AR25-338A_BRICKSTORM.yar"
        hardening_note = "Added nocase to all 13 strings - all are Go symbol paths or plain DNS-over-HTTPS URLs."

    strings:
        $s0 = "main.startNew" nocase
        $s1 = "main.selfWatcher" nocase
        $s2 = "main.setServiceCfg" nocase
        $s3 = "socks.HandleSocksRequest" nocase
        $s4 = "web.WebService" nocase
        $s5 = "command.HandleTTYRequest" nocase
        $s6 = "websocket.(*WSConnector).Connect" nocase
        $s7 = "fs.(*WebServer).RunServer" nocase
        $s8 = "https://1.0.0.1/dns-query" nocase
        $s9 = "https://1.1.1.1/dns-query" nocase
        $s10 = "https://8.8.4.4/dns-query" nocase
        $s11 = "https://8.8.8.8/dns-query" nocase
        $s12 = "https://9.9.9.9/dns-query" nocase

    condition:
        8 of them
}
