rule CISA_251217_03_HARDENED : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "251217"
        family = "BRICKSTORM"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"
        original_rule = "rules/CISA_AR25-338A_BRICKSTORM.yar"
        description = "Hardened version of CISA_251217_03: adds nocase to all strings (HTTP headers, protocol text, and hex identifiers). Detects Rust BRICKSTORM backdoor samples"
        hardening_note = "All 10 strings are printable ASCII text (HTTP headers, WebSocket protocol strings, hex identifiers). All given nocase."

    strings:
        $s0 = " Upgrade: websocketConnection:" nocase
        $s1 = " UpgradeSec-Websocket-Key:" nocase
        $s2 = " Sec-WebSocket-Version:" nocase
        $s3 = "WebSocketSec-WebSocket-Accept:" nocase
        $s4 = "Switching Protocols" nocase
        $s5 = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" nocase
        $s6 = "/dev/ptmxdo forkopen " nocase
        $s7 = "Socks5 cmd not support" nocase
        $s8 = "b92758a9aef1cef7b79e2b72c3d8ba113e547f89" nocase
        $s9 = "X448RingGET \r\n\r\npipePingPongData" nocase

    condition:
        9 of them
}
