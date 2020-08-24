rem @echo off
echo rmccurdy.com BlueTeamPortable


echo [+] Info Checking for admin ...
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
goto theEnd

:noAdmin
echo [+] Error You must run this script as an Administrator!
echo.
pause
exit

:theEnd
 


cd "%~dp0" 


REM Start rekall stuff


REM start-Process "c:\BACKUP\PRIVATE\MobaXterm_Portable\MobaXterm_Portable.bat" -WindowStyle Hidden
rd /q/s output
mkdir output  

 



echo [+] Info Pulling bunch of yara rules ...
title [+] Info Pulling bunch of yara rules ...

  
mkdir yara_rules
cd yara_rules


REM FOR /F "tokens=* delims=" %%A in ('type ..\_SUPPORT\yara_svn_urls.txt ') do ( ..\TortoiseSVN\svn.exe --force export "%%A" >> ..\output\Rekall.log 2>&1 )

REM echo [+] Info Pulling all rules with Powershell in them becuase we can't run all the yara scripts at once...
REM powershell "Get-ChildItem  -Path .\  -Recurse | Select-String -Pattern 'powershell'  | Select Path -Unique  | Get-Content | Out-File ..\Yara_Rules_Powershell.yara"    >> ..\output\_Pull_Yara_Rules.log 2>&1



echo [+] Info Running rekal in live memory mode 


echo [+] Info Running bunch of rekal plugins in live memory mode ( This will take 5-10min)
title [+] Info Running bunch of rekal plugins in live memory mode ( This will take 5-10min)

cd ..\output

"c:\Program Files\rekall\rekal.exe" --live Memory  < ..\_SUPPORT\Rekall_Input_script.txt > .\Rekall.log 2>&1

explorer .\Rekall.log
 


REM START BLUESPAWN STUFF

cd ..

rd /q/s .\downloads 2> %temp%/null

echo [+] Info Downloading wget https://eternallybored.org/misc/wget/1.20.3/64/wget.exe (Warning: May NOT be latest binary !)
powershell "(New-Object Net.WebClient).DownloadFile('https://eternallybored.org/misc/wget/1.20.3/64/wget.exe', '.\wget.exe')"  >> .\output\Rekall.log 2>&1



echo [+] Info Downloading latest BLUESPAWN...
title [+] Info Downloading latest BLUESPAWN...

wget -q -U "rmccurdy.com" -q -P downloads robots=off  -nd -r  "https://github.com/ION28/BLUESPAWN/releases" --max-redirect 1 -l 1 -A "latest,release-*,*x64.exe" -R '*.gz,release*.zip' 

cd ".\downloads"

echo [+] Info Running Intensive scan...
title [+] Info Running Intensive scan...
"BLUESPAWN-client-x64.exe" --hunt -a Intensive    --log=console,xml


echo [+] Info Running Intensive Monitor Mode...
title [+] Info Running Intensive Monitor Mode...
"BLUESPAWN-client-x64.exe" --monitor -a Intensive  --log=console,xml









