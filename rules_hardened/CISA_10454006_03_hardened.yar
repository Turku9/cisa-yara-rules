rule CISA_10454006_03_HARDENED : SUBMARINE trojan backdoor loader rootkit virus controls_local_machine hides_artifacts infects_files installs_other_components remote_access exploitation information_gathering
{
    meta:
        author = "CISA Code & Media Analysis (hardened by cisa-yara-rules project)"
        incident = "10454006"
        date = "2023-07-03"
        family = "SUBMARINE"
        description = "Hardened version of CISA_10454006_03: adds nocase to all strings (all are plain text). Detects SUBMARINE launcher script samples"
        sha256_1 = "bbbae0455f8c98cc955487125a791052353456c8f652ddee14f452415c0b235a"
        source_report = "MAR-10454006-r1.v2"
        source_url = "https://www.cisa.gov/news-events/analysis-reports/ar23-209a"
        original_rule = "rules/CISA_10454006_SUBMARINE_Barracuda.yar"
        hardening_note = "Added nocase to all 12 strings."

    strings:
        $s1 = "sed -i" nocase
        $s2 = "LD_PRELOAD=" nocase
        $s3 = "libutil.so" nocase
        $s4 = "/sbin/smtpctl" nocase
        $s5 = "/boot/os_tools" nocase
        $s6 = "rm -rf" nocase
        $s7 = "base64 -d" nocase
        $s8 = "|sh" nocase
        $s9 = "restart" nocase
        $s10 = "/dev/null" nocase
        $s11 = "#! /bin/sh" nocase
        $s12 = "base64" nocase

    condition:
        filesize < 2KB and all of them
}
