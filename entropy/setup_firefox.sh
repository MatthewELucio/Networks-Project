 # 1) Kill any existing Firefox processes
taskkill /IM firefox.exe /F 2>$null

# 2) Set the environment variable for THIS PowerShell process
$env:SSLKEYLOGFILE="$env:USERPROFILE\sslkeys.txt"

# 3) Sanity check: print it back
$env:SSLKEYLOGFILE

# 4) Start Firefox from this same PowerShell
Start-Process "C:\Program Files\Mozilla Firefox\firefox.exe"