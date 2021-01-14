rule google_creds {
    meta:
        author = "@_batsec_"
        plugin = "google_parse"
    strings: 
        $str1 = "mail.google.com" 
        $str2 = "ServiceLogin%3Fcontinue" 
        $str3 = "req="
    condition: 
        $str1 and $str2 or $str3
}