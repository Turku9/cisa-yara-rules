rule CISA_261290_01 : FIRESTARTER backdoor captures_system_state_data cleans_traces_of_infection fingerprints_host persists_after_system_reboot
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "261290"
        date = "2026-04-03"
        last_modified = "20260406_732"
        actor = "n/a"
        family = "n/a"
        capabilities = "captures-system-state-data cleans-traces-of-infection fingerprints-host persists-after-system-reboot"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects CISCO Firepower FIRESTARTER injector samples"
        source_report = "MAR-261290.r1.v1"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"

    strings:
        $s1 = { 57 48 C1 EF 0C 48 C1 E7 0C BA 07 00 00 00 48 C7 C6 00 20 00 00 }
        $s2 = { 2f 6f 70 74 2f 63 69 73 63 6f 2f 70 6c 61 74 66 6f 72 6d 2f 6c 6f 67 73 2f 76 61 72 2f 6c 6f 67 2f }
        $s3 = { 2f 6f 70 74 2f 63 69 73 63 6f 2f 63 6f 6e 66 69 67 2f 70 6c 61 74 66 6f 72 6d 2f 72 6d 64 62 2f }
        $s4 = { 2f 76 61 72 2f 72 75 6e 2f 72 75 6e 6c 65 76 65 6c }
        $s5 = { 2f 70 72 6f 63 2f 25 73 2f 63 6f 6d 6d }
        $s6 = { 2f 70 72 6f 63 2f 25 64 2f 6d 61 70 73 }
        $s7 = { 2f 61 73 61 2f 62 69 6e 2f 6c 69 6e 61 }

    condition:
        5 of them
}

rule CISA_261290_02 : FIRESTARTER_shellcode backdoor captures_system_state_data cleans_traces_of_infection fingerprints_host persists_after_system_reboot
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "261290"
        date = "2026-04-03"
        last_modified = "20260406_732"
        actor = "n/a"
        family = "n/a"
        capabilities = "captures-system-state-data cleans-traces-of-infection fingerprints-host persists-after-system-reboot"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects CISCO Firepower FIRESTARTER_shellcode samples"
        source_report = "MAR-261290.r1.v1"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"

    strings:
        $s1 = { 57 4C 8B 47 18 4D 85 C0 0F 84 C7 01 00 00 49 8B 38 48 85 FF }
        $s2 = { 48 83 C6 08 4C 39 C6 0F 87 7A 01 00 00 4C 8B 0E }
        $s3 = { 48 89 D7 4C 89 CE B9 D0 01 00 F3 A4 48 89 D7 57 48 C1 EF 0C 48 C1 E7 0C }
        $s4 = { 0F 05 58 5F FF E0 90 90 }

    condition:
        3 of them
}
