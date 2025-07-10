rule Suspicious_PE_File {
    meta:
        description = "Detects suspicious PE files with potential malicious characteristics"
        author = "ThreatScanUSB"
        severity = "medium"
        date = "2023-03-01"
    
    strings:
        $autorun_string = "AutoRun" nocase
        $exec_string1 = "CreateProcess" nocase
        $exec_string2 = "ShellExecute" nocase
        $exec_string3 = "WinExec" nocase
        $registry_string1 = "RegSetValue" nocase
        $registry_string2 = "RegCreateKey" nocase
        $persistence1 = "CurrentVersion\\Run" nocase
        $persistence2 = "StartUp" nocase
        $persistence3 = "UserInit" nocase
        $obf_string1 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }  // Potential obfuscation pattern
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header (PE file)
        (
            ($autorun_string and 1 of ($exec_string*)) or
            (2 of ($exec_string*) and 1 of ($registry_string*)) or
            (1 of ($persistence*) and 1 of ($exec_string*)) or
            $obf_string1
        )
}

rule Suspicious_Script_File {
    meta:
        description = "Detects suspicious script files with potential malicious code"
        author = "ThreatScanUSB"
        severity = "medium"
        date = "2023-03-01"
    
    strings:
        $vbs_wscript = "WScript" nocase
        $vbs_shell = "CreateObject(\"WScript.Shell\")" nocase
        $vbs_network = "CreateObject(\"WScript.Network\")" nocase
        $vbs_exec = ".Run" nocase
        $vbs_hidden = "0, true" nocase or "0,true" nocase
        $ps_download = "DownloadFile" nocase
        $ps_webclient = "Net.WebClient" nocase
        $ps_hidden = "-WindowStyle Hidden" nocase
        $ps_encoded = "-EncodedCommand" nocase
        $bat_net = "net user" nocase
        $bat_reg = "reg add" nocase
        $js_eval = "eval(" nocase
        $js_doc_write = "document.write(unescape(" nocase
        
    condition:
        (
            (any of ($vbs*) and ($vbs_shell or $vbs_network) and $vbs_exec) or
            (any of ($ps*) and ($ps_download or $ps_webclient or $ps_encoded)) or
            (any of ($bat*)) or
            (any of ($js*))
        )
}

rule AutoRun_Infection {
    meta:
        description = "Detects autorun.inf files with suspicious content"
        author = "ThreatScanUSB"
        severity = "high"
        date = "2023-03-01"
    
    strings:
        $autorun_header = "[autorun]" nocase
        $open_string = "open=" nocase
        $shell_string = "shell\\open\\command=" nocase
        $shell_explore = "shell\\explore\\command=" nocase
        $action_string = "action=" nocase
        $icon_string = "icon=" nocase
        $exe_extension = ".exe" nocase
        $scr_extension = ".scr" nocase
        $cmd_extension = ".cmd" nocase
        $bat_extension = ".bat" nocase
        $hidden_attrib = "ATTRIB +S +H" nocase
        
    condition:
        $autorun_header at 0 and 
        (
            ($open_string and any of ($exe_extension, $scr_extension, $cmd_extension, $bat_extension)) or
            ($shell_string) or
            ($shell_explore) or
            ($hidden_attrib)
        )
} 