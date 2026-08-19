rule CISA_251165_02 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251165"
        date = "2025-09-29"
        last_modified = "20251001_1008"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "aaf5569c8e349c15028bc3fac09eb982efb06eabac955b705a6d447263658e38"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"

    strings:
        $s0 = { 6D 61 69 6E 2E 73 74 61 72 74 4E 65 77 }
        $s1 = { 6D 61 69 6E 2E 73 65 6C 66 57 61 74 63 68 65 72 }
        $s2 = { 6D 61 69 6E 2E 73 65 74 53 65 72 76 69 63 65 43 66 67 }
        $s3 = { 73 6F 63 6B 73 2E 48 61 6E 64 6C 65 53 6F 63 6B 73 52 65 71 75 65 73 74 }
        $s4 = { 77 65 62 2E 57 65 62 53 65 72 76 69 63 65 }
        $s5 = { 63 6F 6D 6D 61 6E 64 2E 48 61 6E 64 6C 65 54 54 59 52 65 71 75 65 73 74 }
        $s6 = { 77 65 62 73 6F 63 6B 65 74 2E 28 2A 57 53 43 6F 6E 6E 65 63 74 6F 72 29 2E 43 6F 6E 6E 65 63 74 }
        $s7 = { 66 73 2E 28 2A 57 65 62 53 65 72 76 65 72 29 2E 52 75 6E 53 65 72 76 65 72 }
        $s8 = { 68 74 74 70 73 3A 2F 2F 31 2E 30 2E 30 2E 31 2F 64 6E 73 2D 71 75 65 72 79 }
        $s9 = { 68 74 74 70 73 3A 2F 2F 31 2E 31 2E 31 2E 31 2F 64 6E 73 2D 71 75 65 72 79 }
        $s10 = { 68 74 74 70 73 3A 2F 2F 38 2E 38 2E 34 2E 34 2F 64 6E 73 2D 71 75 65 72 79 }
        $s11 = { 68 74 74 70 73 3A 2F 2F 38 2E 38 2E 38 2E 38 2F 64 6E 73 2D 71 75 65 72 79 }
        $s12 = { 68 74 74 70 73 3A 2F 2F 39 2E 39 2E 39 2E 39 2F 64 6E 73 2D 71 75 65 72 79 }

    condition:
        8 of them
}

rule CISA_251155_02 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251155"
        date = "2025-09-15"
        last_modified = "20250916_1511"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "320a0b5d4900697e125cebb5ff03dee7368f8f087db1c1570b0b62f5a986d759"
        sha256_2 = "dfac2542a0ee65c474b91d3b352540a24f4e223f1b808b741cfe680263f0ee44"
        sha256_3 = "b91881cb1aa861138f2063ec130b2b01a8aaf0e3f04921e5cbfc61b09024bf12"
        sha256_4 = "bfb3ffd46b21b2281374cd60bc756fe2dcc32486dcc156c9bd98f24101145454"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"

    strings:
        $s0 = { 04 30 0F B6 54 04 2C 31 D1 88 4C 04 34 48 FF C0 }
        $s1 = { 48 83 F8 04 7C E7 48 C7 04 24 }
        $s2 = { 48 8D 44 24 34 48 89 44 24 08 48 C7 44 24 10 04 }
        $s3 = { 48 89 44 24 48 48 89 4C 24 50 48 8B 6C 24 38 48 }
        $s4 = { 48 83 EC 40 48 89 6C 24 38 48 8D 6C 24 38 C7 44 24 }
        $s5 = { 83 EC 38 48 89 6C 24 30 48 8D 6C 24 30 C6 44 24 }
        $s6 = { 4C 24 20 48 89 44 24 40 48 89 4C 24 48 48 8B 6C }
        $s7 = { 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 0F 86 81 }
        $s8 = { 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 0F 86 91 }

    condition:
        all of them
}

rule CISA_251155_01 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251155"
        date = "2025-09-15"
        last_modified = "20250916_1511"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "2bf9bfa1f9bcbcad0eada7e3be8d380d809248f08609f6e9d971b37ce09f7e93"
        sha256_2 = "6d42e9a0757670b9837034b5202d1673093577757b44bb0f0253f366413393e9"
        sha256_3 = "b30041b986ee3231fd53522c9d0c57e4567d6c60959fa06c125dde2af558fc9f"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"

    strings:
        $s0 = { 88 14 08 48 FF C1 }
        $s1 = { 2F 63 6F 72 65 2F 74 61 73 6B 2E 44 6F 54 61 73 6B 2E 66 75 6E 63 31 }
        $s2 = { 2F 63 6F 72 65 2F 74 61 73 6B 2E 44 6F 54 61 73 6B 2E 66 75 6E 63 31 2E 32 }
        $s3 = { 2F 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 77 65 62 2E 57 65 62 53 65 72 76 69 63 65 }
        $s4 = { 2F 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 77 65 62 2E 57 65 62 53 65 72 76 69 63 65 2E 66 75 6E 63 31 }
        $s5 = { 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 73 6F 63 6B 73 2E 53 6F 63 6B 73 }
        $s6 = { 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 73 6F 63 6B 73 2E 53 6F 63 6B 73 2E 66 75 6E 63 31 }
        $s7 = { 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 63 6F 6D 6D 61 6E 64 2E 43 6F 6D 6D 61 6E 64 }
        $s8 = { 6C 69 62 73 2F 64 6F 68 2E 51 75 65 72 79 }
        $s9 = { 2F 76 65 6E 64 6F 72 2F 68 61 73 68 69 63 6F 72 70 2F 79 61 6D 75 78 2E 53 65 72 76 65 72 }

    condition:
        3 of them
}

rule CISA_251217_03 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251217"
        date = "2025-12-10"
        last_modified = "20251216_0729"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Rust BRICKSTORM backdoor samples"
        sha256_1 = "6a67a9769a55ec889a5dd4199b2fc08965d39d737838836853bc13c81c56a800"
        sha256_2 = "ed907d39efd5750236b075ca9fbb1f090d7bf578578c38faab24210d298a60ae"
        sha256_3 = "0e92009fc6519c837982b3fbfd42946e827de47b73a264d693739168533d07f4"
        sha256_4 = "fb22eea57e00b83edad50ee6e02320377efc10586584c476d5018dbba3643c32"
        sha256_5 = "28a16e782f04d9394b5dfa3363d41d9f5eecc206166aeffd73363d83734a026d"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"

    strings:
        $s0 = { 20 55 70 67 72 61 64 65 3A 20 77 65 62 73 6F 63 6B 65 74 43 6F 6E 6E 65 63 74 69 6F 6E 3A }
        $s1 = { 20 55 70 67 72 61 64 65 53 65 63 2D 57 65 62 73 6F 63 6B 65 74 2D 4B 65 79 3A }
        $s2 = { 20 53 65 63 2D 57 65 62 53 6F 63 6B 65 74 2D 56 65 72 73 69 6F 6E 3A }
        $s3 = { 57 65 62 53 6F 63 6B 65 74 53 65 63 2D 57 65 62 53 6F 63 6B 65 74 2D 41 63 63 65 70 74 3A }
        $s4 = { 53 77 69 74 63 68 69 6E 67 20 50 72 6F 74 6F 63 6F 6C 73 }
        $s5 = { 32 35 38 45 41 46 41 35 2D 45 39 31 34 2D 34 37 44 41 2D 39 35 43 41 2D 43 35 41 42 30 44 43 38 35 42 31 31 }
        $s6 = { 2F 64 65 76 2F 70 74 6D 78 64 6F 20 66 6F 72 6B 6F 70 65 6E 20 }
        $s7 = { 53 6F 63 6B 73 35 20 63 6D 64 20 6E 6F 74 20 73 75 70 70 6F 72 74 }
        $s8 = { 62 39 32 37 35 38 61 39 61 65 66 31 63 65 66 37 62 37 39 65 32 62 37 32 63 33 64 38 62 61 31 31 33 65 35 34 37 66 38 39 }
        $s9 = { 58 34 34 38 52 69 6E 67 47 45 54 20 0D 0A 0D 0A 70 69 70 65 50 69 6E 67 50 6F 6E 67 44 61 74 61 }

    condition:
        9 of them
}

rule CISA_251155_03 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251155"
        date = "2025-09-15"
        last_modified = "20250916_1511"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "0cba5c6d16c7b94a450c36bfbaeab79107ac10aa9548b02c42b4b6ba8cef6a51"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"

    strings:
        $s0 = { CE 73 63 44 0F B6 04 30 44 31 C7 48 83 FE 19 72 DA EB 53 48 C7 04 24 }
        $s1 = { 64 48 8B 0C 25 F8 FF FF FF 48 8D 44 24 E8 48 3B }
        $s2 = { 8D 44 24 5F 48 89 04 24 48 8D 05 F9 4C 12 00 48 }
        $s3 = { 8B 4C 24 20 48 89 4C 24 30 48 8D 54 24 58 48 89 }
        $s4 = { 8B 44 24 20 48 89 44 24 30 48 8B 4C 24 18 48 89 }
        $s5 = { E8 8E 6A D5 FF 48 8B 44 24 18 48 89 84 24 98 }
        $s6 = { E8 A4 69 D5 FF 48 8B 44 24 20 48 8B 4C 24 28 48 89 84 24 B0 }
        $s7 = { 48 8D 44 24 3F 48 89 44 24 08 48 C7 44 24 10 19 }

    condition:
        all of them
}

rule CISA_251186_02 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251186"
        date = "2025-11-17"
        last_modified = "n/a"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "57bd98dbb5a00e54f07ffacda1fea91451a0c0b532cd7d570e98ce2ff741c21d"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"

    strings:
        $s0 = { 31 F7 40 88 7C 04 4C 48 FF C0 }
        $s1 = { 44 01 C7 40 88 7C 14 30 48 FF C2 0F 1F 00 }
        $s2 = { 41 89 F0 31 FE 01 D6 66 90 49 83 F8 11 }
        $s3 = { 48 8B 44 24 08 48 8B 5C 24 10 48 8B 4C 24 18 }
        $s4 = { 48 89 C1 48 89 DF 48 8D 05 0F 6F 15 00 }
        $s5 = { 48 8D 3D 9A 6D 15 00 4D 89 C1 49 89 F0 }
        $s6 = { 81 39 49 43 4D 50 74 0C }
        $s7 = { E8 FB E6 FF FF E8 76 D0 FF FF E8 91 C0 FF FF 48 8B 05 EA BF 53 }

    condition:
        all of them
}

rule CISA_261234_01 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "261234"
        date = "2026-02-03"
        last_modified = "20260203_1426"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects AOT BRICKSTORM backdoor samples"
        sha256_1 = "24a11a26a2586f4fba7bfe89df2e21a0809ad85069e442da98c37c4add369a0c"
        source_report = "AR25-338A"
        source_url = "https://media.defense.gov/2025/Dec/04/2003834878/-1/-1/0/MALWARE-ANALYSIS-REPORT-BRICKSTORM-BACKDOOR.PDF"

    strings:
        $s0 = { 2F 00 75 00 73 00 72 00 2F 00 73 00 62 00 69 00 6E 00 2F 00 73 00 71 00 69 00 75 00 64 }
        $s1 = { 2F 00 62 00 69 00 6E 00 2F 00 62 00 61 00 73 00 68 }
        $s2 = { 2F 00 63 00 6D 00 64 00 6C 00 69 00 6E 00 65 }
        $s3 = { 2F 00 64 00 65 00 76 00 2F 00 6E 00 75 00 6C }
        $s4 = { 2F 00 65 00 74 00 63 00 2F 00 73 00 61 00 6D 00 62 00 61 00 2F 00 73 00 6D 00 62 }
        $s5 = { 2F 00 70 00 72 00 6F 00 63 00 2F 00 6E 00 65 00 74 00 2F 00 72 00 6F 00 75 00 74 }
        $s6 = { 44 6F 74 4E 65 74 52 75 6E 74 69 6D 65 44 65 62 75 67 48 65 61 64 65 72 }
        $s7 = { 32 35 38 45 41 46 41 35 2D 45 39 31 34 2D 34 37 44 41 2D 39 35 43 41 2D 43 35 41 42 30 44 43 38 35 42 31 31 }
        $s8 = { 63 66 73 65 74 6F 73 70 65 65 64 00 63 68 64 69 72 00 63 6C 6F 73 65 00 64 75 70 32 }
        $s9 = { 65 78 65 63 76 00 65 78 65 63 76 70 00 66 6F 72 6B 00 66 6F 72 6B 70 74 79 00 6B 69 6C 6C }
        $s10 = { 32 31 35 31 30 31 32 31 33 62 35 63 34 35 34 38 61 62 36 63 63 65 38 31 38 35 34 61 31 33 65 65 }

    condition:
        9 of them
}
