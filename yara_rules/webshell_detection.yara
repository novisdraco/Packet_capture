
rule Web_Shell_Detection {
    meta:
        description = "Detects web shell patterns in HTTP traffic"
        author = "Security Team"
        severity = "High"
        
    strings:
        $php1 = "<?php eval("
        $php2 = "<?php system("
        $php3 = "<?php exec("
        $php4 = "<?php shell_exec("
        $php5 = "<?php passthru("
        
        $asp1 = "<%eval request"
        $asp2 = "<%execute request"
        
        $jsp1 = "<%Runtime.getRuntime().exec("
        $jsp2 = "<%Process p = Runtime"
        
        $generic1 = "webshell"
        $generic2 = "backdoor"
        $generic3 = "c99shell"
        $generic4 = "r57shell"
        
    condition:
        any of them
}
