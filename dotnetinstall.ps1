# this script isn't part of Group3r it's just a hack to make GithHub Actions build it properly.

$ProgressPreference = 'SilentlyContinue'
Write-Host "Downloading .NET Framework 4.5.2 SDK"
invoke-webrequest -uri "https://go.microsoft.com/fwlink/?linkid=397673&clcid=0x409" -OutFile framework-installer.exe

Write-Host "Installing .NET Framework SDK"
.\framework-installer.exe /q /norestart
Wait-Process -name "framework-installer"

Write-Host ".Net Framework 4.5.2 should be installed now."