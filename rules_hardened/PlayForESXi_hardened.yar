rule PlayForESXi_HARDENED
{
    meta:
        description = "Hardened version of PlayForESXi: adds nocase to resist case-swap evasion. Detects PLAY ransomware targeting ESXi Hypervisors"
        date = "2025-01"
        filetype = "elf"
        maltype = "ransomware"
        author = "CISA / FBI / ASD's ACSC (hardened by cisa-yara-rules project)"
        source_report = "AA23-352A"
        source_url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"
        original_rule = "rules/CISA_AA23-352A_PlayRansomware_GRXBA.yar"
        hardening_note = "Added nocase modifier to all text strings. No other changes to detection logic."

    strings:
        $encrypt_str = "encrypt:" nocase
        $first_step_str = "First step is done." nocase
        $vmfs_path_str = "/vmfs/volumes" nocase
        $PLAY_ext_str = ".PLAY" nocase fullword
        $stop_list_mode_str = "stop list mode" nocase
        $hosts_in_exclusion_str = "hosts in exclusion:" nocase
        $error_in_stop_list_str = "Error, check stop list file, exit." nocase
        $complete_str = "Complete." nocase
        $dev_urandom_path_str = "/dev/urandom" nocase
        $targeted_ext_vmdk = ".vmdk" nocase fullword
        $targeted_ext_vmem = ".vmem" nocase fullword
        $targeted_ext_vmsd = ".vmsd" nocase fullword
        $targeted_ext_vmsn = ".vmsn" nocase fullword
        $targeted_ext_vmx = ".vmx" nocase fullword
        $targeted_ext_vmxf = ".vmxf" nocase fullword
        $targeted_ext_vswp = ".vswp" nocase fullword
        $targeted_ext_vmss = ".vmss" nocase fullword
        $targeted_ext_nvram = ".nvram" nocase fullword
        $targeted_ext_vmtx = ".vmtx" nocase fullword
        $targeted_ext_log = ".log" nocase fullword
        $vim_cmd_power_off_vms_str = "vim-cmd vmsvc/power.off" nocase
        $get_storage_shell_cmd_str = "esxcli storage filesystem list > storage" nocase
        $get_machines_shell_cmd_str = "vim-cmd vmsvc/getallvms > machines" nocase
        $base64_encoded_24_byte_val = /[A-Za-z0-9+\/=]{33}/

    condition:
        all of them
}
