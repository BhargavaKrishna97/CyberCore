/*
  CyberCore YARA Ransomware Detection Rules
  Covers common ransomware families and generic behaviours.
*/

rule ransomware_generic
{
    meta:
        description = "Generic ransomware string detection"
        severity    = "critical"

    strings:
        $a1 = "Your files have been encrypted" nocase
        $a2 = "send bitcoin" nocase
        $a3 = "pay ransom" nocase
        $a4 = "decrypt your files" nocase
        $a5 = "ransom" nocase
        $a6 = "All your files" nocase
        $a7 = "encrypted with" nocase

    condition:
        2 of ($a*)
}


rule ransomware_wannacry
{
    meta:
        description = "WannaCry ransomware indicators"
        severity    = "critical"

    strings:
        $b1 = "WannaDecryptor" nocase
        $b2 = "WANACRY" nocase
        $b3 = "wncry" nocase
        $b4 = "tasksche.exe" nocase
        $b5 = "@WanaDecryptor@" nocase

    condition:
        any of ($b*)
}


rule ransomware_locky
{
    meta:
        description = "Locky ransomware indicators"
        severity    = "critical"

    strings:
        $c1 = "locky" nocase
        $c2 = "_Locky_recover_instructions" nocase
        $c3 = ".locky" nocase

    condition:
        any of ($c*)
}


rule ransomware_ryuk
{
    meta:
        description = "Ryuk ransomware indicators"
        severity    = "critical"

    strings:
        $d1 = "RyukReadMe" nocase
        $d2 = "No system is safe" nocase
        $d3 = "UNIQUE_ID_DO_NOT_REMOVE" nocase

    condition:
        any of ($d*)
}


rule ransomware_extension_change
{
    meta:
        description = "Files with known ransomware extensions"
        severity    = "high"

    strings:
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".cerber"
        $ext4 = ".crypto"
        $ext5 = ".zepto"

    condition:
        any of ($ext*)
}


rule suspicious_encryption_activity
{
    meta:
        description = "Suspicious use of encryption APIs"
        severity    = "medium"

    strings:
        $e1 = "CryptEncrypt" nocase
        $e2 = "AES_encrypt" nocase
        $e3 = "RSA_encrypt" nocase
        $e4 = "DeleteShadowCopies" nocase
        $e5 = "vssadmin delete shadows" nocase
        $e6 = "bcdedit /set" nocase

    condition:
        2 of ($e*)
}
