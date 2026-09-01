rule CISA_261290_01_HARDENED : FIRESTARTER backdoor captures_system_state_data cleans_traces_of_infection fingerprints_host persists_after_system_reboot
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        source_report = "MAR-261290.r1.v1"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
        original_rule = "rules/CISA_MAR-261290_FIRESTARTER.yar"
        description = "Hardened version of CISA_261290_01: adds nocase to file path strings. Detects CISCO Firepower FIRESTARTER injector samples"
        hardening_note = "$s1 is x86 opcode bytes, unchanged. $s2-$s7 are Linux file paths (plain text), all given nocase."

    strings:
        $s1 = { 57 48 C1 EF 0C 48 C1 E7 0C BA 07 00 00 00 48 C7 C6 00 20 00 00 }
        $s2 = "/opt/cisco/platform/logs/var/log/" nocase
        $s3 = "/opt/cisco/config/platform/rmdb/" nocase
        $s4 = "/var/run/runlevel" nocase
        $s5 = "/proc/%s/comm" nocase
        $s6 = "/proc/%d/maps" nocase
        $s7 = "/asa/bin/lina" nocase

    condition:
        5 of them
}
