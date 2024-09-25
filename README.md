Sure, let's continue with the remaining parts of the README:

---

# PowerShell Script for System Setup and Configuration

## Overview

This PowerShell script performs several tasks to set up and configure your system. It includes changing the execution policy, installing various tools and applications on both Windows and Kali Linux, and configuring system settings.

## Prerequisites

- Windows operating system with administrative privileges.
- Internet connection to download necessary files and packages.
- Windows Subsystem for Linux (WSL) with Kali Linux installed.

## Script Details

### Change Execution Policy

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

### Install PowerShell 7

The script installs PowerShell 7.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://github.com/PowerShell/PowerShell/releases/download/v7.2.3/PowerShell-7.2.3-win-x64.msi'))
```

### Install Chocolatey

The script installs the Chocolatey package manager.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

### Install ADB and Fastboot

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

### Install iCloud and iTunes

The script installs iCloud and iTunes on Windows.

```powershell
$icloudInstaller = 'https://secure-appldnld.apple.com/itunes12/001-23456-20210920-ABCDE12345/iCloudSetup.exe'
$itunesInstaller = 'https://secure-appldnld.apple.com/itunes12/001-23456-20210920-ABCDE12345/iTunesSetup.exe'
Invoke-WebRequest -Uri $icloudInstaller -OutFile "$env:TEMP\iCloudSetup.exe"
Invoke-WebRequest -Uri $itunesInstaller -OutFile "$env:TEMP\iTunesSetup.exe"
Start-Process -FilePath "$env:TEMP\iCloudSetup.exe" -ArgumentList '/quiet' -Wait
Start-Process -FilePath "$env:TEMP\iTunesSetup.exe" -ArgumentList '/quiet' -Wait
```

### Install Apktool

The script installs Apktool on Windows.

```powershell
$apktoolInstaller = 'https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.6.1.jar'
$apktoolScript = 'https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat'
Invoke-WebRequest -Uri $apktoolInstaller -OutFile "$env:WINDIR\apktool.jar"
Invoke-WebRequest -Uri $apktoolScript -OutFile "$env:WINDIR\apktool.bat"
```

### Install Ghidra

The script installs Ghidra on Windows.

```powershell
$ghidraInstaller = 'https://ghidra-sre.org/ghidra_10.1.5_PUBLIC_20220210.zip'
Invoke-WebRequest -Uri $ghidraInstaller -OutFile "$env:TEMP\ghidra.zip"
Expand-Archive -Path "$env:TEMP\ghidra.zip" -DestinationPath "C:\Program Files\Ghidra"
```

### Install Wireshark

The script installs Wireshark on both Windows and Kali Linux.

```powershell
# On Windows
choco install wireshark -y

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y wireshark
"
```

### Configure Wireshark to Share Database with Metasploit

The script configures Wireshark to share its database with Metasploit on Kali Linux.

```powershell
wsl -d kali-linux -u root -- bash -c "
echo 'db_connect msf:password@localhost/msf' >> /etc/metasploit/msfconsole.rc
"
```

### Install Ncat

The script installs Ncat on both Windows and Kali Linux.

```powershell
# On Windows
choco install ncat -y

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y ncat
"
```

### Install Pcap Tools

The script installs Pcap tools on both Windows and Kali Linux.

```powershell
# On Windows
choco install npcap -y

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y libpcap-dev
"
```

### Install Hashcat

The script installs Hashcat on both Windows and Kali Linux.

```powershell
# On Windows
choco install hashcat -y

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y hashcat
"
```

### Install Wifite3

The script installs Wifite3 on both Windows and Kali Linux.

```powershell
# On Windows
pip install wifite

# On Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y wifite
"
```

### Change Desktop Wallpaper Every 5 Minutes on Kali Linux

The script sets up a cron job to change the desktop wallpaper every 5 minutes on Kali Linux.

```powershell
wsl -d kali-linux -u root -- bash -c "
apt install -y feh
(crontab -l 2>/dev/null; echo '*/5 * * * * DISPLAY=:0 feh --randomize --bg-fill /usr/share/backgrounds/kali/*.jpg') | crontab -
"
```

### Remove Games and Bloatware from Windows

The script removes games and bloatware from Windows.

```powershell
Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*Xbox*" -or $_.Name -like "*Zune*" -or $_.Name -like "*Bing*" } | Remove-AppxPackage
Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*Xbox*" -or $_.DisplayName -like "*Zune*" -or $_.DisplayName -like "*Bing*" } | Remove-AppxProvisionedPackage -Online
```

### Set Prompt on All Terminals

The script sets a custom prompt on various terminals.

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

Sure, let's continue with the remaining parts of the script:

```powershell
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

# Install youtube-dl on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y youtube-dl
"

# Install Synapse on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y synapse
"

# Install Snapd on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y snapd
systemctl enable --now snapd apparmor
"

# Install Snap Store on Kali Linux
wsl -d kali-linux -u root -- bash -c "
snap install snap-store
"

# Install Gdebi on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y gdebi
"

# Install Kodachi tools on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y tor privoxy bleachbit secure-delete
"

# Install Kodachi tools on Windows
choco install tor -y
choco install privoxy -y
choco install bleachbit -y

# Configure Kodachi privacy settings on Kali Linux
wsl -d kali-linux -u root -- bash -c "
echo 'forward-socks5 / 127.0.0.1:9050 .' >> /etc/privoxy/config
systemctl enable tor
systemctl start tor
systemctl enable privoxy
systemctl start privoxy
"

# Install John the Ripper on Windows
choco install john -y

# Install Hydra on Windows
choco install hydra -y

# Install John the Ripper on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y john
"

# Install Hydra on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y hydra
"

# Download wordlists and username lists
$wordlistUrl = 'https://github.com/danielmiessler/SecLists/archive/master.zip'
Invoke-WebRequest -Uri $wordlistUrl -OutFile "$env:TEMP\SecLists.zip"
Expand-Archive -Path "$env:TEMP\SecLists.zip" -DestinationPath "$env:USERPROFILE\Desktop\SecLists"

# Install TrackView on Windows
$trackviewInstaller = 'http://trackview.net/download/TrackViewSetup.exe'
Invoke-WebRequest -Uri $trackviewInstaller -OutFile "$env:TEMP\TrackViewSetup.exe"
Start-Process -FilePath "$env:TEMP\TrackViewSetup.exe" -ArgumentList '/quiet' -Wait

# Download Android and iOS simulators
$androidSimulatorUrl = 'https://www.osboxes.org/android-x86/'
$iosSimulatorUrl = 'https://appetize.io/demo'

# Download Android simulator
Invoke-WebRequest -Uri $androidSimulatorUrl -OutFile "$env:TEMP\android-x86.ova"

# Download iOS simulator
Invoke-WebRequest -Uri $iosSimulatorUrl -OutFile "$env:TEMP\ios-simulator.ova"

# Install VirtualBox on Windows
choco install virtualbox -y

# Import Android simulator into VirtualBox
Start-Process -FilePath "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" -ArgumentList "import $env:TEMP\android-x86.ova" -Wait

# Import iOS simulator into VirtualBox
Start-Process -FilePath "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" -ArgumentList "import $env:TEMP\ios-simulator.ova" -Wait

# Install VirtualBox on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y virtualbox
"

# Import Android simulator into VirtualBox on Kali Linux
wsl -d kali-linux -u root -- bash -c "
VBoxManage import /mnt/c/Users/$env:USERNAME/TEMP/android-x86.ova
"

# Import iOS simulator into VirtualBox on Kali Linux
wsl -d kali-linux -u root -- bash -c "
VBoxManage import /mnt/c/Users/$env:USERNAME/TEMP/ios-simulator.ova
"

# Set up advanced Nmap scans on Windows
$nmapScriptPath = "$env:USERPROFILE\Desktop\nmap_scan.ps1"
$nmapScriptContent = @"
param (
    [string]`$targetIp
)
nmap -sS -sU -p- -A -O -oN `"$env:USERPROFILE\Desktop\nmap_scan.txt`" `$targetIp
"@
Set-Content -Path $nmapScriptPath -Value $nmapScriptContent

# Set up advanced Nmap scans on Kali Linux
wsl -d kali-linux -u root -- bash -c "
echo 'param (
    [string]`$targetIp
)
nmap -sS -sU -p- -A -O -oN `"/root/nmap_scan.txt`" `$targetIp' > /root/nmap_scan.ps1
"

# Set up script to import Nmap scans into Armitage and launch Armitage on Windows
$armitageScriptPath = "$env:USERPROFILE\Desktop\armitage_import.ps1"
$armitageScriptContent = @"
param (
    [string]`$targetIp
)
& `"$env:ProgramFiles\Armitage\armitage.bat`"
"@
Set-Content -Path $armitageScriptPath -Value $armitageScriptContent

# Set up script to import Nmap scans into Armitage and launch Armitage on Kali Linux
wsl -d kali-linux -u root -- bash -c "
echo 'param (
    [string]`$targetIp
)
armitage' > /root/armitage_import.ps1
"

# Set up script to import Nmap scans into Metasploit and run vulnerability checks on Windows
$metasploitScriptPath = "$env:USERPROFILE\Desktop\metasploit_import.ps1"
$metasploitScriptContent = @"
param (
    [string]`$targetIp
)
msfconsole -x 'db_import `"$env:USERPROFILE\Desktop\nmap_scan.txt`"; vulns'
"@
Set-Content -Path $metasploitScriptPath -Value $metasploitScriptContent

# Set up script to import Nmap scans into Metasploit and run vulnerability checks on Kali Linux
wsl -d kali-linux -u root -- bash -c "
echo 'param (
    [string]`$targetIp
)
msfconsole -x `"'db_import /root/nmap_scan.txt; vulns`"'' > /root/metasploit_import.ps1
"

# Set Kali user name and password
wsl -d kali-linux -u root -- bash -c "
echo 'kali:kali' | chpasswd
echo 'root:password' | chpasswd
"

# Enable RDP on Windows
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'

# Enable VNC on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y tightvncserver
tightvncserver :1
"

# Install FTP server on Windows
choco install filezilla -y

# Install FTP server on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y vsftpd
systemctl enable vsftpd
systemctl start vsftpd
"

# Install SFTP server on Windows
choco install openssh -y

# Install SFTP server on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y openssh-server
systemctl enable ssh
systemctl start ssh
"

# Install XMPP server on Windows
choco install prosody -y

# Install XMPP server on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y prosody
systemctl enable prosody
systemctl start prosody
"
```
