rule CISA_261234_01_HARDENED : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "261234"
        family = "BRICKSTORM"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"
        original_rule = "rules/CISA_AR25-338A_BRICKSTORM.yar"
        description = "Hardened version of CISA_261234_01: converts hex-encoded wide file paths to text with wide+nocase, adds nocase to two plain-text strings. Detects AOT BRICKSTORM backdoor samples"
        hardening_note = "$s0-$s5 were UTF-16 (wide) encoded file paths, rewritten as text with wide+nocase. $s6 (DotNetRuntimeDebugHeader) and $s7 (WebSocket magic GUID) are plain text, given nocase. $s8,$s9 are null-byte-separated lists of syscall names - left as hex to preserve exact separator bytes. $s10 is a 32-char hex identifier, left unchanged (same reasoning as AES keys elsewhere in this repo)."

    strings:
        $s0 = "/usr/sbin/sqiud" wide nocase
        $s1 = "/bin/bash" wide nocase
        $s2 = "/cmdline" wide nocase
        $s3 = "/dev/nul" wide nocase
        $s4 = "/etc/samba/smb" wide nocase
        $s5 = "/proc/net/rout" wide nocase
        $s6 = "DotNetRuntimeDebugHeader" nocase
        $s7 = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" nocase
        $s8 = { 63 66 73 65 74 6F 73 70 65 65 64 00 63 68 64 69 72 00 63 6C 6F 73 65 00 64 75 70 32 }
        $s9 = { 65 78 65 63 76 00 65 78 65 63 76 70 00 66 6F 72 6B 00 66 6F 72 6B 70 74 79 00 6B 69 6C 6C }
        $s10 = "215101213b5c4548ab6cce81854a13ee"

    condition:
        9 of them
}
