rule CISA_10430311_01 : METERPRETER trojan downloader
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10430311"
        date = "2023-03-03"
        last_modified = "20230404_1200"
        actor = "n/a"
        family = "METERPRETER"
        Capabilities = "n/a"
        Malware_Type = "trojan downloader"
        Tool_Type = "n/a"
        description = "Detects trojan downloader samples"
        sha256_1 = "334c2d0af191ed96b15095a4a098c400f2c0ce6b9c66d1800f6b74554d59ff4b"
        source_report = "MAR-10430311.c1.v1"
        source_url = "https://www.cisa.gov/sites/default/files/2023-09/MAR-10430311.c1.v1.CLEAR_.pdf"

    strings:
        $s1 = { 49 be 77 73 32 5f 33 32 }
        $s2 = { 49 89 e6 48 81 ec a0 01 }
        $s3 = { 49 bc 02 00 e5 6b b3 3c 93 04 }
        $s4 = { 41 ba 4c 77 26 07 ff d5 }
        $s5 = { 41 ba ea 0f df e0 ff d5 }
        $s6 = { 41 ba 99 a5 74 61 ff d5 }
        $s7 = { 41 ba 02 d9 c8 5f ff d5 }
        $s8 = { 41 ba 58 a4 53 e5 ff d5 }

    condition:
        all of them
}

rule CISA_10430311_02 : METERPRETER controls_local_machine compromises_data_integrity communicates_with_c2 keylogger exploit_kit remote_access_trojan backdoor downloader screen_capture virus remote_access exploitation network_capture
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10430311"
        date = "2023-03-08"
        last_modified = "20230405_1300"
        actor = "n/a"
        family = "METERPRETER"
        Capabilities = "controls-local-machine compromises-data-integrity communicates-with-c2"
        Malware_Type = "keylogger exploit-kit remote-access-trojan backdoor downloader screen-capture virus"
        Tool_Type = "remote-access exploitation network-capture"
        description = "Detects Fresh Meterpreter binary samples"
        sha256_1 = "79a9136eedbf8288ad7357ddaea3a3cd1a57b7c6f82adffd5a9540e1623bfb63"
        sha256_2 = "334c2d0af191ed96b15095a4a098c400f2c0ce6b9c66d1800f6b74554d59ff4b"
        sha256_3 = "6dcc7b5e913154abac69687fcfb6a58ac66ec9b8cc7de7afd8832a9066b7bdde"
        sha256_4 = "47dacb8f0b157355a4fd59ccbac1c59b8268fe84f3b8a462378b064333920622"
        source_report = "MAR-10430311.c1.v1"
        source_url = "https://www.cisa.gov/sites/default/files/2023-09/MAR-10430311.c1.v1.CLEAR_.pdf"

    strings:
        $s0 = { 58 a4 53 e5 }
        $s1 = { 02 d9 c8 5f }
        $s2 = { 99 a5 74 61 }
        $s3 = { 4c 77 26 07 }
        $s4 = { 29 80 6b 00 }
        $s5 = { 50 41 59 4c 4f 41 44 3a }
        $s6 = { 48 83 ec 28 49 c7 c1 40 }

    condition:
        all of them
}

rule CISA_10430311_03 : ASPX_WEBSHELL webshell
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10430311"
        date = "2023-03-21"
        last_modified = "20230404_1230"
        actor = "n/a"
        family = "ASPX Webshell"
        Capabilities = "n/a"
        Malware_Type = "webshell"
        Tool_Type = "n/a"
        description = "Detects OWA targeting ASPX Webshell samples"
        sha256_1 = "6dcc7b5e913154abac69687fcfb6a58ac66ec9b8cc7de7afd8832a9066b7bdde"
        sha256_2 = "47dacb8f0b157355a4fd59ccbac1c59b8268fe84f3b8a462378b064333920622"
        source_report = "MAR-10430311.c1.v1"
        source_url = "https://www.cisa.gov/sites/default/files/2023-09/MAR-10430311.c1.v1.CLEAR_.pdf"

    strings:
        $s1 = { 5a 30 32 6a 77 36 43 36 63 55 }
        $s2 = { 5a 38 49 30 32 38 33 6e 77 38 }
        $s3 = { 4f 57 41 77 65 62 63 6f 6e 66 69 67 }
        $s4 = { 54 55 43 53 4f 4e }
        $s5 = { 65 76 61 6c }

    condition:
        3 of them
}
