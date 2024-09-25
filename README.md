# My Personal PowerShell Script For The Automated System Setup & Configuration of Windows & Kali Linux WSL 

## Overview

This PowerShell script performs several tasks to set up and configure your system. It includes changing the execution policy, installing various tools and applications on both Windows and Kali Linux, and configuring system settings.

### Prerequisites

- Windows operating system with administrative privileges.
- Internet connection to download necessary files and packages.
- Windows Subsystem for Linux (WSL) with Kali Linux installed.

## Script Details

### Change Execution Policy For Powershell on Windows

The script changes the PowerShell execution policy to `Unrestricted` to allow all scripts to run.

```powershell
# Check the current execution policy
$currentPolicy = Get-ExecutionPolicy
Write-Output "Current Execution Policy: $currentPolicy"

# Change the execution policy to Unrestricted
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force

# Verify the new execution policy
$newPolicy = Get-ExecutionPolicy
Write-Output "New Execution Policy: $newPolicy"
```

### Install PowerShell 7 on Windows & Kali Linux WSL

The script installs PowerShell 7.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://github.com/PowerShell/PowerShell/releases/download/v7.2.3/PowerShell-7.2.3-win-x64.msi'))
```

### Install Chocolatey (Choco) on Windows

The script installs the Chocolatey package manager.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

### Install ADB & Fastboot on Windows & Kali Linux WSL

The script installs ADB and Fastboot on both Windows and Kali Linux.

```powershell
# On Windows
choco install adb -y
choco install fastboot -y

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y android-tools-adb android-tools-fastboot
"
```

### Install iCloud & iTunes on Windows

The script installs iCloud and iTunes on Windows.

```powershell
$icloudInstaller = 'https://secure-appldnld.apple.com/itunes12/001-23456-20210920-ABCDE12345/iCloudSetup.exe'
$itunesInstaller = 'https://secure-appldnld.apple.com/itunes12/001-23456-20210920-ABCDE12345/iTunesSetup.exe'
Invoke-WebRequest -Uri $icloudInstaller -OutFile "$env:TEMP\iCloudSetup.exe"
Invoke-WebRequest -Uri $itunesInstaller -OutFile "$env:TEMP\iTunesSetup.exe"
Start-Process -FilePath "$env:TEMP\iCloudSetup.exe" -ArgumentList '/quiet' -Wait
Start-Process -FilePath "$env:TEMP\iTunesSetup.exe" -ArgumentList '/quiet' -Wait
```

### Install APK Tools on Windows

The script installs Apktool on Windows.

```powershell
$apktoolInstaller = 'https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.6.1.jar'
$apktoolScript = 'https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat'
Invoke-WebRequest -Uri $apktoolInstaller -OutFile "$env:WINDIR\apktool.jar"
Invoke-WebRequest -Uri $apktoolScript -OutFile "$env:WINDIR\apktool.bat"
```

### Install NSA's Ghidra on Windows

The script installs Ghidra on Windows.

```powershell
$ghidraInstaller = 'https://ghidra-sre.org/ghidra_10.1.5_PUBLIC_20220210.zip'
Invoke-WebRequest -Uri $ghidraInstaller -OutFile "$env:TEMP\ghidra.zip"
Expand-Archive -Path "$env:TEMP\ghidra.zip" -DestinationPath "C:\Program Files\Ghidra"
```

### Install Wireshark on Windows & Kali Linux WSL

The script installs Wireshark on both Windows and Kali Linux WSL.

```powershell
# On Windows
choco install wireshark -y

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y wireshark
"
```

### Configure Wireshark to Share Database with Metasploit on Kali Linux

The script configures Wireshark to share its database with Metasploit on Kali Linux WSL.

```powershell
wsl -d kali-linux -u root -- bash -c "
echo 'db_connect msf:password@localhost/msf' >> /etc/metasploit/msfconsole.rc
"
```

### Install NCAT on Windows & Kali Linux WSL

The script installs Ncat on both Windows and Kali Linux WSL.

```powershell
# On Windows
choco install ncat -y

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y ncat
"
```

### Install PCAP Tools on Windows & Kali Linux WSL

The script installs Pcap tools on both Windows and Kali Linux WSL.

```powershell
# On Windows
choco install npcap -y

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y libpcap-dev
"
```

### Install Hashcat on Windows and Kali WSL

The script installs Hashcat on both Windows and Kali Linux WSL.

```powershell
# On Windows
choco install hashcat -y

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y hashcat
"
```

### Install Wifite3 on Windows & Kali Linux WSL

The script installs Wifite3 on both Windows and Kali Linux WSL.

```powershell
# On Windows
pip install wifite

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y wifite
"
```

### Change Desktop Wallpaper Every 5 Minutes on Kali Linux WSL

The script sets up a cron job to change the desktop wallpaper every 5 minutes on Kali Linux WSL.

```powershell
wsl -d kali-linux -u root -- bash -c "
apt install -y feh
(crontab -l 2>/dev/null; echo '*/5 * * * * DISPLAY=:0 feh --randomize --bg-fill /usr/share/backgrounds/kali/*.jpg') | crontab -
"
```

### Remove Games & Bloatware From Windows

The script removes games and bloatware from Windows.

```powershell
Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*Xbox*" -or $_.Name -like "*Zune*" -or $_.Name -like "*Bing*" } | Remove-AppxPackage
Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*Xbox*" -or $_.DisplayName -like "*Zune*" -or $_.DisplayName -like "*Bing*" } | Remove-AppxProvisionedPackage -Online
```

### Set Prompt on All Terminals on Windows & Kali Linux WSL 

The script sets a custom prompt on various terminals on both Windows & Kali Linux WSL.

```powershell
$prompt = 'IEatDicks@ndGobbleBalls:  '

# Windows PowerShell
$profilePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
if (-not (Test-Path -Path $profilePath)) {
    New-Item -ItemType File -Path $profilePath -Force
}
Add-Content -Path $profilePath -Value "`nfunction prompt { '$prompt' }"

# Bash
$bashProfilePath = "$env:USERPROFILE\.bashrc"
if (-not (Test-Path -Path $bashProfilePath)) {
    New-Item -ItemType File -Path $bashProfilePath -Force
}
Add-Content -Path $bashProfilePath -Value "`nPS1='$prompt'"

# Zsh
$zshProfilePath = "$env:USERPROFILE\.zshrc"
if (-not (Test-Path -Path $zshProfilePath)) {
    New-Item -ItemType File -Path $zshProfilePath -Force
}
Add-Content -Path $zshProfilePath -Value "`nPROMPT='$prompt'"

# Git
$gitProfilePath = "$env:USERPROFILE\.gitconfig"
if (-not (Test-Path -Path $gitProfilePath)) {
    New-Item -ItemType File -Path $gitProfilePath -Force
}
Add-Content -Path $gitProfilePath -Value "`n[core]\n    prompt = $prompt"

# Python
$pythonProfilePath = "$env:USERPROFILE\.pythonrc"
if (-not (Test-Path -Path $pythonProfilePath)) {
    New-Item -ItemType File -Path $pythonProfilePath -Force
}
Add-Content -Path $pythonProfilePath -Value "`nimport sys\nsys.ps1 = '$prompt'"

# Kali Linux
wsl -d kali-linux -u root -- bash -c "
echo 'PS1=\"$prompt\"' >> /root/.bashrc
echo 'PROMPT=\"$prompt\"' >> /root/.zshrc
echo '[core]\n    prompt = $prompt' >> /root/.gitconfig
echo 'import sys\nsys.ps1 = \"$prompt\"' >> /root/.

# Python
$pythonProfilePath = "$env:USERPROFILE\.pythonrc"

if (-not (Test-Path -Path $pythonProfilePath)) {
    New-Item -ItemType File -Path $pythonProfilePath -Force
}
Add-Content -Path $pythonProfilePath -Value "`nimport sys\nsys.ps1 = '$prompt'"

# Kali Linux
wsl -d kali-linux -u root -- bash -c "
echo 'PS1=\"$prompt\"' >> /root/.bashrc
echo 'PROMPT=\"$prompt\"' >> /root/.zshrc
echo '[core]\n    prompt = $prompt' >> /root/.gitconfig
echo 'import sys\nsys.ps1 = \"$prompt\"' >> /root/.pythonrc
"
```

### Installs youtube-dl on Kali Linux WSL
```powershell
# Install youtube-dl on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y youtube-dl
"
```

### Install Synapse on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y synapse
"
```

### Install Snapd on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y snapd
systemctl enable --now snapd apparmor
"
```

### Install Snap Store on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
snap install snap-store
"
```

### Install Gdebi on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y gdebi
"
```

### Install Kodachi Tools on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y tor privoxy bleachbit secure-delete
"
```

### Install Kodachi Tools on Windows
```powershell
choco install tor -y
choco install privoxy -y
choco install bleachbit -y
```

### Configure Kodachi Linux Privacy Settings on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
echo 'forward-socks5 / 127.0.0.1:9050 .' >> /etc/privoxy/config
systemctl enable tor
systemctl start tor
systemctl enable privoxy
systemctl start privoxy
"
```

### Install John The Ripper on Windows
```powershell
choco install john -y
```

### Install Hydra on Windows
```powershell
choco install hydra -y
```

### Download Wordlists & Username Lists on Windows
```powershell
$wordlistUrl = 'https://github.com/danielmiessler/SecLists/archive/master.zip'
Invoke-WebRequest -Uri $wordlistUrl -OutFile "$env:TEMP\SecLists.zip"
Expand-Archive -Path "$env:TEMP\SecLists.zip" -DestinationPath "$env:USERPROFILE\Desktop\SecLists"
```

### Install TrackView on Windows
```powershell
$trackviewInstaller = 'http://trackview.net/download/TrackViewSetup.exe'
Invoke-WebRequest -Uri $trackviewInstaller -OutFile "$env:TEMP\TrackViewSetup.exe"
Start-Process -FilePath "$env:TEMP\TrackViewSetup.exe" -ArgumentList '/quiet' -Wait
```

### Download Android & iOS Simulators on Windows
```powershell
$androidSimulatorUrl = 'https://www.osboxes.org/android-x86/'
$iosSimulatorUrl = 'https://appetize.io/demo'
```

### Download Android Simulator on Windows
```powershell
Invoke-WebRequest -Uri $androidSimulatorUrl -OutFile "$env:TEMP\android-x86.ova"
```

### Download iOS Simulator on Windows
```powershell
Invoke-WebRequest -Uri $iosSimulatorUrl -OutFile "$env:TEMP\ios-simulator.ova"
```

### Install VirtualBox on Windows
```powershell
choco install virtualbox -y
```

### Import Android Simulator into VirtualBox on Windows
```powershell
Start-Process -FilePath "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" -ArgumentList "import $env:TEMP\android-x86.ova" -Wait
```

### Import iOS Simulator into VirtualBox on Windows
```powershell
Start-Process -FilePath "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" -ArgumentList "import $env:TEMP\ios-simulator.ova" -Wait
```

### Install VirtualBox on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y virtualbox
"
```

### Import Android Simulator into VirtualBox on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
VBoxManage import /mnt/c/Users/$env:USERNAME/TEMP/android-x86.ova
"
```

### Import iOS Simulator into VirtualBox on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
VBoxManage import /mnt/c/Users/$env:USERNAME/TEMP/ios-simulator.ova
"
```

### Setup Advanced Nmap Scans on Windows
```powershell
$nmapScriptPath = "$env:USERPROFILE\Desktop\nmap_scan.ps1"
$nmapScriptContent = @"
param (
    [string]`$targetIp
)
nmap -sS -sU -p- -A -O -oN `"$env:USERPROFILE\Desktop\nmap_scan.txt`" `$targetIp
"@
Set-Content -Path $nmapScriptPath -Value $nmapScriptContent
```

### Setup Advanced Nmap Scans on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
echo 'param (
    [string]`$targetIp
)
nmap -sS -sU -p- -A -O -oN `"/root/nmap_scan.txt`" `$targetIp' > /root/nmap_scan.ps1
"
```

### Setup Script to Import Nmap Scans into Armitage & Launch Armitage on Windows
```powershell
$armitageScriptPath = "$env:USERPROFILE\Desktop\armitage_import.ps1"
$armitageScriptContent = @"
param (
    [string]`$targetIp
)
& `"$env:ProgramFiles\Armitage\armitage.bat`"
"@
Set-Content -Path $armitageScriptPath -Value $armitageScriptContent
```

### Setup Script to Import Nmap Scans into Armitage & Launch Armitage on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
echo 'param (
    [string]`$targetIp
)
armitage' > /root/armitage_import.ps1
"
```

### Setup Script to Import Nmap Scans into Metasploit Framework & Run Vulnerability Checks on Windows
```powershell
$metasploitScriptPath = "$env:USERPROFILE\Desktop\metasploit_import.ps1"
$metasploitScriptContent = @"
param (
    [string]`$targetIp
)
msfconsole -x 'db_import `"$env:USERPROFILE\Desktop\nmap_scan.txt`"; vulns'
"@
Set-Content -Path $metasploitScriptPath -Value $metasploitScriptContent
```

### Setup Script to Import Nmap Scans into Metasploit Framework & Run Vulnerability Checks on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
echo 'param (
    [string]`$targetIp
)
msfconsole -x `"'db_import /root/nmap_scan.txt; vulns`"'' > /root/metasploit_import.ps1
"
```

### Set Kali User Name & Password on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
echo 'kali:kali' | chpasswd
echo 'root:password' | chpasswd
"
```

### Enable Remote Desktop Platform (RDP) on Windows
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
```

### Enable VNC on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y tightvncserver
tightvncserver :1
"
```

### Install FTP Server on Windows
```powershell
choco install filezilla -y
```

### Install FTP Server on Kali Linux WSL 
```powershell
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y vsftpd
systemctl enable vsftpd
systemctl start vsftpd
"
```

### Install SFTP Server on Windows
```powershell
choco install openssh -y
```

### Install SFTP Server on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y openssh-server
systemctl enable ssh
systemctl start ssh
"
```

### Install XAMPP Server on Windows
```powershell
choco install prosody -y
```

### Install XAMPP Server on Kali Linux WSL
```powershell
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y prosody
systemctl enable prosody
systemctl start prosody
"
```
