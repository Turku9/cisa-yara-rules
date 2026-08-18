rule PlayForESXi
{
    meta:
        description = "Detects PLAY ransomware targeting ESXi Hypervisors"
        date = "2025-01"
        filetype = "elf"
        maltype = "ransomware"
        author = "CISA / FBI / ASD's ACSC"
        source_report = "AA23-352A"
        source_url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"

    strings:
        $encrypt_str = "encrypt:"
        $first_step_str = "First step is done."
        $vmfs_path_str = "/vmfs/volumes"
        $PLAY_ext_str = ".PLAY" fullword
        $stop_list_mode_str = "stop list mode"
        $hosts_in_exclusion_str = "hosts in exclusion:"
        $error_in_stop_list_str = "Error, check stop list file, exit."
        $complete_str = "Complete."
        $dev_urandom_path_str = "/dev/urandom"
        $targeted_ext_vmdk = ".vmdk" fullword
        $targeted_ext_vmem = ".vmem" fullword
        $targeted_ext_vmsd = ".vmsd" fullword
        $targeted_ext_vmsn = ".vmsn" fullword
        $targeted_ext_vmx = ".vmx" fullword
        $targeted_ext_vmxf = ".vmxf" fullword
        $targeted_ext_vswp = ".vswp" fullword
        $targeted_ext_vmss = ".vmss" fullword
        $targeted_ext_nvram = ".nvram" fullword
        $targeted_ext_vmtx = ".vmtx" fullword
        $targeted_ext_log = ".log" fullword
        $vim_cmd_power_off_vms_str = "vim-cmd vmsvc/power.off"
        $get_storage_shell_cmd_str = "esxcli storage filesystem list > storage"
        $get_machines_shell_cmd_str = "vim-cmd vmsvc/getallvms > machines"
        $base64_encoded_24_byte_val = /[A-Za-z0-9+\/=]{33}/

    condition:
        all of them
}

rule GRXBA
{
    meta:
        description = "Detects the infostealer GRXBA version 1.1.3.0"
        date = "2025-01"
        filetype = "pe"
        maltype = "infostealer"
        author = "CISA / FBI / ASD's ACSC"
        source_report = "AA23-352A"
        source_url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"

    strings:
        $GRB_NET_hex = { 47 52 42 5F 4E 45 54 }
        $GRB_NET_exe_hex = { 47 52 42 5F 4E 45 54 2E 65 78 65 00 }
        $Copyright_Zabbix_2023_hex = { 43 6F 70 79 72 69 67 68 74 20 5A 61 62 62 69 78 20 32 30 32 33 00 }
        $GRB_NT_hex = { 47 52 42 5F 4E 54 00 }
        $help_string_1_hex = { 48 65 6C 70 54 65 78 74 2B 46 69 6C 65 2E 74 78 74 2F 31 32 37 2E 30 2E 30 2E 31 2D 31 32 37 2E 30 2E 30 2E 32 35 35 2F 31 32 37 2E 30 2E 30 2E 31 2D 32 34 }
        $help_string_2_hex = { 48 65 6C 70 54 65 78 74 5E 44 6F 6D 61 69 6E 20 6E 61 6D 65 20 66 6F 72 20 55 73 65 72 73 20 61 6E 64 20 43 6F 6D 70 75 74 65 72 73 20 67 61 74 68 65 72 69 6E 67 2E 20 49 66 20 6E 6F 74 20 73 65 74 20 77 69 6C 6C 20 62 65 20 75 73 65 64 20 64 6F 6D 61 69 6E 20 6F 66 20 63 75 72 72 65 6E 74 20 75 73 65 72 }
        $help_string_3_hex = { 48 65 6C 70 54 65 78 74 62 47 52 42 20 6D 6F 64 65 2E 20 73 63 61 6E 2F 73 63 61 6E 61 6C 6C 2F 63 6C 72 2E 20 73 63 61 6E 20 2D 20 6E 65 74 77 6F 72 6B 20 73 63 61 6E 6E 65 72 2E 20 73 63 61 6E 61 6C 6C 20 2D 20 67 72 61 62 20 61 6C 6C 2E 20 20 63 6C 72 20 2D 20 65 76 65 6E 74 20 6C 6F 67 73 20 63 6C 65 61 6E 65 72 }
        $help_string_4_hex = { 48 65 6C 70 54 65 78 74 3A 49 6E 70 75 74 3A 20 66 2F 72 2F 73 2E 20 66 20 2D 20 66 69 6C 65 2C 20 72 20 2D 20 72 61 6E 67 65 2C 20 73 20 2D 20 73 75 62 6E 65 74 2C 20 64 20 2D 20 64 6F 6D 61 69 6E }

    condition:
        all of them
}
