rule CISA_251155_01_HARDENED : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "251155"
        family = "BRICKSTORM"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"
        original_rule = "rules/CISA_AR25-338A_BRICKSTORM.yar"
        description = "Hardened version of CISA_251155_01: adds nocase to Go package path strings. Opcode string ($s0) left unchanged."
        hardening_note = "$s0 is x86 opcode bytes, unchanged. $s1-$s9 are Go package/function paths, all given nocase."

    strings:
        $s0 = { 88 14 08 48 FF C1 }
        $s1 = "/core/task.DoTask.func1" nocase
        $s2 = "/core/task.DoTask.func1.2" nocase
        $s3 = "/core/extends/web.WebService" nocase
        $s4 = "/core/extends/web.WebService.func1" nocase
        $s5 = "core/extends/socks.Socks" nocase
        $s6 = "core/extends/socks.Socks.func1" nocase
        $s7 = "core/extends/command.Command" nocase
        $s8 = "libs/doh.Query" nocase
        $s9 = "/vendor/hashicorp/yamux.Server" nocase

    condition:
        3 of them
}
