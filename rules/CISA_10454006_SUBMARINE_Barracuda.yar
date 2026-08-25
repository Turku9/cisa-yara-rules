import "math"

rule CISA_10454006_01 : SUBMARINE trojan backdoor remote_access_trojan remote_access information_gathering exploitation determines_c2_server controls_local_machine compromises_data_integrity
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10452108"
        date = "2023-06-29"
        last_modified = "20230711_1500"
        actor = "n/a"
        family = "SUBMARINE"
        capabilities = "determines-c2-server controls-local-machine compromises-data-integrity"
        malware_type = "trojan backdoor remote-access-trojan"
        tool_type = "remote-access information-gathering exploitation"
        description = "Detects SUBMARINE Barracuda backdoor samples"
        sha256_1 = "81cf3b162a4fe1f1b916021ec652ade4a14df808021eeb9f7c81c8d2326bddab"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"

    strings:
        $s1 = { 32 35 30 2d 6d 61 69 6c 32 2e 65 63 63 65 6e 74 72 69 63 2e 64 75 63 6b }
        $s2 = { 6f 70 65 6e 73 73 6c 20 61 65 73 2d 32 35 36 }
        $s3 = { 65 63 68 6f 20 2d 6e 20 27 25 73 27 20 7c 20 62 61 73 65 36 34 20 2d 64 }
        $s4 = { 2d 69 76 }
        $s5 = { 48 65 6c 6c 6f 20 25 73 20 5b 25 73 5d 2c 20 70 6c 65 61 73 65 64 20 74 6f 20 6d 65 65 74 20 79 6f 75 }
        $s6 = { e8 47 fa ff }
        $s7 = { 63 6f 6d 6d 61 6e 64 }
        $s8 = { 2d 69 76 20 36 39 38 32 32 62 36 63 }
        $s9 = { 73 65 6e 64 }
        $s10 = { 73 6f 63 6B 65 74 }
        $s11 = { 63 6f 6e 6e 65 63 74 }

    condition:
        filesize < 15KB and 8 of them
}

rule CISA_10454006_02 : SUBMARINE trojan backdoor exploitation hides_artifacts prevents_artifact_access
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10454006"
        date = "2023-06-29"
        last_modified = "20230711_1500"
        actor = "n/a"
        family = "SUBMARINE"
        capabilities = "hides-artifacts prevents-artifact-access"
        malware_type = "trojan backdoor"
        tool_type = "exploitation"
        description = "Detects encoded GZIP archive samples"
        sha256_1 = "6dd8de093e391da96070a978209ebdf9d807e05c89dba13971be5aea2e1251d0"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"

    strings:
        $s1 = { 48 34 73 49 41 41 41 41 41 41 41 41 41 2b 30 61 }
        $s2 = { 44 44 44 41 67 50 39 2f 2b 43 38 47 70 2f 36 63 41 46 41 41 41 41 3d 3d 0a }
        $s3 = { 37 56 4d 70 56 58 4f 37 2b 6d 4c 39 78 2b 50 59 }

    condition:
        filesize < 6KB and 3 of them and (math.entropy(0,filesize) > 5.8)
}

rule CISA_10454006_03 : SUBMARINE trojan backdoor loader rootkit virus controls_local_machine hides_artifacts infects_files installs_other_components remote_access exploitation information_gathering
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10454006"
        date = "2023-07-03"
        last_modified = "20230711_1500"
        actor = "n/a"
        family = "SUBMARINE"
        capabilities = "controls-local-machine hides-artifacts infects-files installs-other-components"
        malware_type = "trojan backdoor loader rootkit virus"
        tool_type = "remote-access exploitation information-gathering"
        description = "Detects SUBMARINE launcher script samples"
        sha256_1 = "bbbae0455f8c98cc955487125a791052353456c8f652ddee14f452415c0b235a"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"

    strings:
        $s1 = { 73 65 64 20 2d 69 }
        $s2 = { 4c 44 5f 50 52 45 4c 4f 41 44 3d }
        $s3 = { 6c 69 62 75 74 69 6c 2e 73 6f }
        $s4 = { 2f 73 62 69 6e 2f 73 6d 74 70 63 74 6c }
        $s5 = { 2f 62 6f 6f 74 2f 6f 73 5f 74 6f 6f 6c 73 }
        $s6 = { 72 6d 20 2d 72 66 }
        $s7 = { 62 61 73 65 36 34 20 2d 64 }
        $s8 = { 7c 73 68 }
        $s9 = { 72 65 73 74 61 72 74 }
        $s10 = { 2f 64 65 76 2f 6e 75 6c 6c }
        $s11 = { 23 21 20 2f 62 69 6e 2f 73 68 }
        $s12 = { 62 61 73 65 36 34 }

    condition:
        filesize < 2KB and all of them
}

rule CISA_10454006_04 : SUBMARINE trojan backdoor hides_artifacts hides_executing_code infects_files installs_other_components remote_access exploitation
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10454006"
        date = "2023-07-05"
        last_modified = "20230711_1500"
        actor = "n/a"
        family = "SUBMARINE"
        capabilities = "hides-artifacts hides-executing-code infects-files installs-other-components"
        malware_type = "trojan backdoor"
        tool_type = "remote-access exploitation"
        description = "Detects SUBMARINE launcher script samples"
        sha256_1 = "b98f8989e8706380f779bfd464f3dea87c122651a7a6d06a994d9a4758e12e43"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"

    strings:
        $s1 = { 73 6c 65 65 70 }
        $s2 = { 7c 62 61 73 65 36 34 20 2d 64 }
        $s3 = { 4c 44 5f 50 52 45 4c 4f 41 44 }
        $s4 = { 2f 68 6f 6d 65 2f 70 72 6f 64 75 63 74 2f 63 6f 64 65 2f 66 69 72 6d 77 61 72 65 2f 63 75 72 72 65 6e 74 2f 73 62 69 6e 2f 73 6d 74 70 63 74 6c 20 72 65 73 74 61 72 74 }
        $s5 = { 65 63 68 6f 20 2d 6e 20 27 }
        $s6 = { 73 68 }
        $s7 = { 23 21 20 2f 62 69 6e 2f 73 68 }

    condition:
        filesize < 2KB and 6 of them
}

rule CISA_10454006_05 : SUBMARINE trojan backdoor remote_access_trojan compromises_data_integrity cleans_traces_of_infection hides_artifacts installs_other_components remote_access exploitation
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10454006"
        date = "2023-07-05"
        last_modified = "20230711_1500"
        actor = "n/a"
        family = "SUBMARINE"
        capabilities = "compromises-data-integrity cleans-traces-of-infection hides-artifacts installs-other-components"
        malware_type = "trojan backdoor remote-access-trojan"
        tool_type = "remote-access exploitation"
        description = "Detects SUBMARINE launcher script samples"
        sha256_1 = "cc131dd1976a47ee3b631a136c3224a138716e9053e04d8bea3ee2e2c5de451a"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"

    strings:
        $s1 = { 4c 44 5f 50 52 45 4c 4f 41 44 }
        $s2 = { 23 21 20 2f 62 69 6e 2f 73 68 }
        $s3 = { 4c 44 5f 50 52 45 4c 4f 41 44 3d 2f 62 6f 6f 74 2f 6f 73 5f 74 6f 6f 6c 73 2f 6c 69 62 75 74 69 6c 2e 73 6f 20 65 78 65 63 }
        $s4 = { 3e 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 }
        $s5 = { 62 73 6d 74 70 64 20 63 6f 6e 74 72 6f 6c 20 73 63 72 69 70 74 }
        $s6 = { 42 53 4d 54 50 44 5f 50 49 44 }
        $s7 = { 2f 72 65 6c 6f 61 64 2f 72 65 73 74 61 72 74 }

    condition:
        filesize < 6KB and 6 of them
}

rule CISA_10454006_06 : SUBMARINE trojan backdoor cleans_traces_of_infection hides_artifacts installs_other_components
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10454006"
        date = "2023-07-11"
        last_modified = "20230727_1200"
        actor = "n/a"
        family = "SUBMARINE"
        capabilities = "cleans-traces-of-infection hides-artifacts installs-other-components"
        malware_type = "trojan backdoor"
        tool_type = "unknown"
        description = "Detects SUBMARINE SQL trigger samples"
        sha256_1 = "2a353e9c250e5ea905fa59d33faeaaa197d17b4a4785456133aab5dbc1d1d5d5"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"

    strings:
        $s1 = { 54 52 49 47 47 45 52 }
        $s2 = { 43 52 45 41 54 45 }
        $s3 = { 53 45 4c 45 43 54 20 22 65 63 68 6f 20 2d 6e }
        $s4 = { 62 61 73 65 36 34 20 2d 64 20 7c 20 73 68 }
        $s5 = { 72 6f 6f 74 }
        $s6 = { 53 45 54 }
        $s7 = { 45 4e 44 20 49 46 3b }
        $s8 = { 48 34 73 49 41 41 41 41 41 41 41 41 41 2b 30 61 43 33 42 55 }
        $s9 = { 2f 76 61 72 2f 74 6d 70 2f 72 }
        $s10 = { 2f 72 6f 6f 74 2f 6d 61 63 68 69 6e 65 }

    condition:
        filesize < 250KB and all of them
}

rule CISA_10454006_07 : SUBMARINE trojan dropper exploit_kit evades_av hides_executing_code hides_artifacts exploitation
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10454006"
        date = "2023-07-11"
        last_modified = "20230711_1830"
        actor = "n/a"
        family = "SUBMARINE"
        capabilities = "evades-av hides-executing-code hides-artifacts"
        malware_type = "trojan dropper exploit-kit"
        tool_type = "exploitation"
        description = "Detects ESG FileName exploit samples"
        sha256_1 = "8695945155d3a87a5733d31bf0f4c897e133381175e1a3cdc8c73d9e38640239"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"

    strings:
        $s1 = { 7c 20 62 61 73 65 36 34 20 2d 64 20 7c 20 73 68 }
        $s2 = { 65 63 68 6f 20 2d 6e }
        $s3 = { 59 32 46 30 49 43 39 32 59 58 49 76 64 47 31 77 4c 33 49 67 66 43 42 69 59 58 4e 6c 4e 6a 51 67 4c 57 51 67 4c 57 6b 67 66 43 42 30 59 58 49 67 }

    condition:
        filesize < 1KB and all of them
}
