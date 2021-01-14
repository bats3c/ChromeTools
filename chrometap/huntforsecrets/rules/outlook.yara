rule outlook_creds {
    meta:
        author = "@_batsec_"
        plugin = "outlook_parse"
    strings: 
        $str1 = "login.live.com" 
        $str2 = "login=" 
        $str3 = "hisScaleUnit="
        $str4 = "passwd="
    condition: 
        all of them 
}