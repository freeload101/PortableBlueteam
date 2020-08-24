@echo off
REM start-Process "c:\BACKUP\PRIVATE\MobaXterm_Portable\MobaXterm_Portable.bat" -WindowStyle Hidden
mkdir output >> ..\output\Rekall.log 2>&1
del .\output\Rekall.log >> ..\output\Rekall.log 2>&1

del .\yara_rules\Yara_Rules_Powershell.yara >> ..\output\Rekall.log 2>&1


echo [+] Info Running bunch of rekal plugins in live memory mode ( This will take 5-10min)

cd .\output

"c:\Program Files\rekall\rekal.exe" --live Memory  < ..\_SUPPORT\Rekall_Input_script.txt >> ..\output\Rekall.log 2>&1



echo [+] Info Pulling bunch of yara rules ...

cd ..
 
mkdir yara_rules
cd yara_rules


FOR /F "tokens=* delims=" %%A in ('type ..\_SUPPORT\yara_svn_urls.txt ') do ( ..\TortoiseSVN\svn.exe --force export "%%A" >> ..\output\Rekall.log 2>&1 )
 