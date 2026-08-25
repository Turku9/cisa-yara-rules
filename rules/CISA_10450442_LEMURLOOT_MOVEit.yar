rule CISA_10450442_01 : LEMURLOOT webshell communicates_with_c2 remote_access
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10450442"
        date = "2023-06-07"
        last_modified = "20230609_1200"
        actor = "n/a"
        family = "LEMURLOOT"
        capabilities = "communicates-with-c2"
        malware_type = "webshell"
        tool_type = "remote-access"
        description = "Detects ASPX webshell samples"
        sha256_1 = "3a977446ed70b02864ef8cfa3135d8b134c93ef868a4cc0aa5d3c2a74545725b"
        source_report = "AA23-158A"
        source_url = "https://www.cisa.gov/sites/default/files/2023-07/aa23-158a-stopransomware-cl0p-ransomware-gang-exploits-moveit-vulnerability_8.pdf"

    strings:
        $s1 = { 4d 4f 56 45 69 74 2e 44 4d 5a }
        $s2 = { 25 40 20 50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d }
        $s3 = { 4d 79 53 51 4c }
        $s4 = { 41 7a 75 72 65 }
        $s5 = { 58 2d 73 69 4c 6f 63 6b 2d }

    condition:
        all of them
}
