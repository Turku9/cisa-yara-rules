rule CISA_10375867_01_HARDENED : wiper HERMETICWIPER
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        category = "Wiper"
        source_report = "AR22-115A"
        source_url = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-115a"
        original_rule = "rules/CISA_10375867_HermeticWiper.yar"
        description = "Hardened version of CISA_10375867_01: rewrites hex-encoded wide strings as text with 'wide nocase' modifiers for case-insensitive matching. Detects Hermetic Wiper samples"
        hardening_note = "All original hex strings were UTF-16 (wide) encoded plain text (registry paths, privilege names, driver names). Rewritten as text strings with 'wide nocase' modifiers, which is both more readable and adds case-insensitivity that raw hex bytes could not provide."

    strings:
        $rsrc1 = "SZDD" ascii nocase
        $rsrc2 = "RCDATA" wide nocase
        $rsrc3 = "DRV_X64" wide nocase
        $rsrc4 = "DRV_X86" wide nocase
        $rsrc5 = "DRV_XP_X64" wide nocase
        $rsrc6 = "DRV_XP_X86" wide nocase
        $s1 = "EPMNTDRV\\%u" wide nocase
        $s2 = "PhysicalDrive%u" wide nocase
        $s3 = "SYSTEM\\CurrentControlSet\\Control\\CrashControl" wide nocase
        $s4 = "CrashDumpEnabled" wide nocase
        $s5 = "$INDEX_ALLOCATION" wide nocase
        $s6 = "SeLoadDriverPrivilege" wide nocase
        $s7 = "SeBackupPrivilege" wide nocase
        $s8 = "C:\\Windows\\SYSVOL" wide nocase

    condition:
        uint16(0) == 0x5A4D and ((3 of ($rsrc*)) and (7 of ($s*)))
}
