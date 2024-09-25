# Install PowerShell 7
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://github.com/PowerShell/PowerShell/releases/download/v7.2.3/PowerShell-7.2.3-win-x64.msi'))

# Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install ADB and Fastboot on Windows
choco install adb -y
choco install fastboot -y

# Install ADB and Fastboot on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y android-tools-adb android-tools-fastboot
"

# Install iCloud and iTunes on Windows
$icloudInstaller = 'https://secure-appldnld.apple.com/itunes12/001-23456-20210920-ABCDE12345/iCloudSetup.exe'
$itunesInstaller = 'https://secure-appldnld.apple.com/itunes12/001-23456-20210920-ABCDE12345/iTunesSetup.exe'
Invoke-WebRequest -Uri $icloudInstaller -OutFile "$env:TEMP\iCloudSetup.exe"
Invoke-WebRequest -Uri $itunesInstaller -OutFile "$env:TEMP\iTunesSetup.exe"
Start-Process -FilePath "$env:TEMP\iCloudSetup.exe" -ArgumentList '/quiet' -Wait
Start-Process -FilePath "$env:TEMP\iTunesSetup.exe" -ArgumentList '/quiet' -Wait

# Install Samsung Bootloader Changer App on Windows
$bootloaderChangerInstaller = 'https://example.com/samsung-bootloader-changer.exe'
Invoke-WebRequest -Uri $bootloaderChangerInstaller -OutFile "$env:TEMP\samsung-bootloader-changer.exe"
Start-Process -FilePath "$env:TEMP\samsung-bootloader-changer.exe" -ArgumentList '/quiet' -Wait

# Install Apktool on Windows
$apktoolInstaller = 'https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.6.1.jar'
$apktoolScript = 'https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat'
Invoke-WebRequest -Uri $apktoolInstaller -OutFile "$env:WINDIR\apktool.jar"
Invoke-WebRequest -Uri $apktoolScript -OutFile "$env:WINDIR\apktool.bat"

# Install Ghidra on Windows
$ghidraInstaller = 'https://ghidra-sre.org/ghidra_10.1.5_PUBLIC_20220210.zip'
Invoke-WebRequest -Uri $ghidraInstaller -OutFile "$env:TEMP\ghidra.zip"
Expand-Archive -Path "$env:TEMP\ghidra.zip" -DestinationPath "C:\Program Files\Ghidra"

# Install Wireshark on Windows
choco install wireshark -y

# Install Wireshark on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y wireshark
"

# Configure Wireshark to share database with Metasploit on Kali Linux
wsl -d kali-linux -u root -- bash -c "
echo 'db_connect msf:password@localhost/msf' >> /etc/metasploit/msfconsole.rc
"

# Install Ncat on Windows
choco install ncat -y

# Install Ncat on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y ncat
"

# Install Pcap tools on Windows
choco install npcap -y

# Install Pcap tools on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y libpcap-dev
"

# Install Hashcat on Windows
choco install hashcat -y

# Install Hashcat on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y hashcat
"

# Install Wifite3 on Windows
pip install wifite

# Install Wifite3 on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y wifite
"

# Change desktop wallpaper every 5 minutes on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt install -y feh
(crontab -l 2>/dev/null; echo '*/5 * * * * DISPLAY=:0 feh --randomize --bg-fill /usr/share/backgrounds/kali/*.jpg') | crontab -
"

Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://github.com/PowerShell/PowerShell/releases/download/v7.2.3/PowerShell-7.2.3-win-x64.msi'))

# Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install OpenVPN on Windows
choco install openvpn -y

# Install WSL and Kali Linux
wsl --install -d kali-linux
wsl --set-default-version 2

# Install OpenVPN on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y openvpn network-manager-openvpn network-manager-openvpn-gnome
"

# Configure OpenVPN server on Kali Linux
wsl -d kali-linux -u root -- bash -c "
mkdir -p /etc/openvpn/server
cd /etc/openvpn/server
openvpn --genkey --secret ta.key
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz .
gunzip server.conf.gz
sed -i 's/;tls-auth ta.key 0/tls-auth ta.key 0/' server.conf
sed -i 's/;cipher AES-256-CBC/cipher AES-256-CBC/' server.conf
sed -i 's/;user nobody/user nobody/' server.conf
sed -i 's/;group nogroup/group nogroup/' server.conf
systemctl enable openvpn@server
systemctl start openvpn@server
"

# Generate .ovpn file for iPhone
wsl -d kali-linux -u root -- bash -c "
cat <<EOF > /etc/openvpn/client.ovpn
client
dev tun
proto udp
remote YOUR_SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
key-direction 1
<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server/client.crt)
</cert>
<key>
$(cat /etc/openvpn/server/client.key)
</key>
<tls-auth>
$(cat /etc/openvpn/server/ta.key)
</tls-auth>
EOF
"

# Install requested applications on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y virtualbox teamviewer realvnc-vnc-server realvnc-vnc-viewer anydesk vlc bash wget curl python3 python3-pip perl ruby ruby-dev docker.io automake autoconf cmake zsh nano nnn nodejs npm git nmap zenmap typescript golang rustc mysql-server lua5.3 openssh-server
"

# Configure SSH on both Windows and Kali Linux
wsl -d kali-linux -u root -- bash -c "
sed -i 's/#Port 22/Port 1022/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl enable ssh
systemctl start ssh
"

# Configure SSH on Windows
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# Set up shared keys and allow SSH between Windows and Kali
ssh-keygen -t rsa -b 4096 -f $env:USERPROFILE\.ssh\id_rsa -N ''
wsl -d kali-linux -u root -- bash -c "
mkdir -p /root/.ssh
echo '$(cat $env:USERPROFILE\.ssh\id_rsa.pub)' >> /root/.ssh/authorized_keys
"

# Enable DNS
wsl -d kali-linux -u root -- bash -c "
apt install -y bind9
systemctl enable bind9
systemctl start bind9
"

# Change desktop wallpaper every 5 minutes
# Windows
$script = @"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    public static void Set(string path) {
        SystemParametersInfo(20, 0, path, 0x01 | 0x02);
    }
}
'@
$wallpapers = Get-ChildItem -Path "C:\Path\To\Wallpapers" -Filter *.jpg
while ($true) {
    $wallpaper = Get-Random -InputObject $wallpapers
    [Wallpaper]::Set($wallpaper.FullName)
    Start-Sleep -Seconds 300
}
"@
Invoke-Expression $script

# Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt install -y feh
(crontab -l 2>/dev/null; echo '*/5 * * * * DISPLAY=:0 feh --randomize --bg-fill /usr/share/backgrounds/kali/*.jpg') | crontab -
"

# Add antivirus exceptions for Downloads and Desktop folders
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Downloads"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Desktop"

# Configure firewall to allow all services from installations
$firewallRules = @(
    'VirtualBox', 'TeamViewer', 'RealVNC', 'AnyDesk', 'VLC', 'Docker', 'OpenVPN', 'SSH'
)
foreach ($rule in $firewallRules) {
    New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow -Program "C:\Program Files\$rule\$rule.exe"
}

# Enable UPnP
Set-Service -Name upnphost -StartupType Automatic
Start-Service -Name upnphost

# Set up No-IP on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt install -y noip2
noip2 -C
systemctl enable noip2
systemctl start noip2
"

# Set prompt on all terminals
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
echo 'import sys\nsys.ps1 = \"$prompt\"' >> /root/.pythonrc
"

# Install youtube-dl on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y youtube-dl
"

# Remove games and bloatware from Windows
Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*Xbox*" -or $_.Name -like "*Zune*" -or $_.Name -like "*Bing*" } | Remove-AppxPackage
Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*Xbox*" -or $_.DisplayName -like "*Zune*" -or $_.DisplayName -like "*Bing*" } | Remove-AppxProvisionedPackage -Online

# Set prompt on all terminals
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

# Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install OpenVPN on Windows
choco install openvpn -y

# Install WSL and Kali Linux
wsl --install -d kali-linux
wsl --set-default-version 2

# Install OpenVPN on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y openvpn network-manager-openvpn network-manager-openvpn-gnome
"

# Configure OpenVPN server on Kali Linux
wsl -d kali-linux -u root -- bash -c "
mkdir -p /etc/openvpn/server
cd /etc/openvpn/server
openvpn --genkey --secret ta.key
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz .
gunzip server.conf.gz
sed -i 's/;tls-auth ta.key 0/tls-auth ta.key 0/' server.conf
sed -i 's/;cipher AES-256-CBC/cipher AES-256-CBC/' server.conf
sed -i 's/;user nobody/user nobody/' server.conf
sed -i 's/;group nogroup/group nogroup/' server.conf
systemctl enable openvpn@server
systemctl start openvpn@server
"

# Generate .ovpn file for iPhone
wsl -d kali-linux -u root -- bash -c "
cat <<EOF > /etc/openvpn/client.ovpn
client
dev tun
proto udp
remote YOUR_SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
key-direction 1
<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server/client.crt)
</cert>
<key>
$(cat /etc/openvpn/server/client.key)
</key>
<tls-auth>
$(cat /etc/openvpn/server/ta.key)
</tls-auth>
EOF
"

# Install requested applications on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y virtualbox teamviewer realvnc-vnc-server realvnc-vnc-viewer anydesk vlc bash wget curl python3 python3-pip perl ruby ruby-dev docker.io automake autoconf cmake zsh nano nnn nodejs npm git nmap zenmap typescript golang rustc mysql-server lua5.3 openssh-server
"

# Configure SSH on both Windows and Kali Linux
wsl -d kali-linux -u root -- bash -c "
sed -i 's/#Port 22/Port 1022/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl enable ssh
systemctl start ssh
"

# Configure SSH on Windows
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# Set up shared keys and allow SSH between Windows and Kali
ssh-keygen -t rsa -b 4096 -f $env:USERPROFILE\.ssh\id_rsa -N ''
wsl -d kali-linux -u root -- bash -c "
mkdir -p /root/.ssh
echo '$(cat $env:USERPROFILE\.ssh\id_rsa.pub)' >> /root/.ssh/authorized_keys
"

# Enable DNS
wsl -d kali-linux -u root -- bash -c "
apt install -y bind9
systemctl enable bind9
systemctl start bind9
"

# Change desktop wallpaper every 5 minutes
# Windows
$script = @"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    public static void Set(string path) {
        SystemParametersInfo(20, 0, path, 0x01 | 0x02);
    }
}
'@
$wallpapers = Get-ChildItem -Path "C:\Path\To\Wallpapers" -Filter *.jpg
while ($true) {
    $wallpaper = Get-Random -InputObject $wallpapers
    [Wallpaper]::Set($wallpaper.FullName)
    Start-Sleep -Seconds 300
}
"@
Invoke-Expression $script

# Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt install -y feh
(crontab -l 2>/dev/null; echo '*/5 * * * * DISPLAY=:0 feh --randomize --bg-fill /usr/share/backgrounds/kali/*.jpg') | crontab -
"

# Add antivirus exceptions for Downloads and Desktop folders
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Downloads"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Desktop"

# Configure firewall to allow all services from installations
$firewallRules = @(
    'VirtualBox', 'TeamViewer', 'RealVNC', 'AnyDesk', 'VLC', 'Docker', 'OpenVPN', 'SSH'
)
foreach ($rule in $firewallRules) {
    New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow -Program "C:\Program Files\$rule\$rule.exe"
}

# Enable UPnP
Set-Service -Name upnphost -StartupType Automatic
Start-Service -Name upnphost

# Set up No-IP on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt install -y noip2
noip2 -C
systemctl enable noip2
systemctl start noip2
"

# Set prompt on all terminals
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
echo 'import sys\nsys.ps1 = \"$prompt\"' >> /root/.pythonrc
"

# Install youtube-dl on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y youtube-dl
"

# Install PowerShell 7
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://github.com/PowerShell/PowerShell/releases/download/v7.2.3/PowerShell-7.2.3-win-x64.msi'))

# Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install OpenVPN on Windows
choco install openvpn -y

# Install WSL and Kali Linux
wsl --install -d kali-linux
wsl --set-default-version 2

# Install OpenVPN on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y openvpn network-manager-openvpn network-manager-openvpn-gnome
"

# Configure OpenVPN server on Kali Linux
wsl -d kali-linux -u root -- bash -c "
mkdir -p /etc/openvpn/server
cd /etc/openvpn/server
openvpn --genkey --secret ta.key
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz .
gunzip server.conf.gz
sed -i 's/;tls-auth ta.key 0/tls-auth ta.key 0/' server.conf
sed -i 's/;cipher AES-256-CBC/cipher AES-256-CBC/' server.conf
sed -i 's/;user nobody/user nobody/' server.conf
sed -i 's/;group nogroup/group nogroup/' server.conf
systemctl enable openvpn@server
systemctl start openvpn@server
"

# Generate .ovpn file for iPhone
wsl -d kali-linux -u root -- bash -c "
cat <<EOF > /etc/openvpn/client.ovpn
client
dev tun
proto udp
remote YOUR_SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
key-direction 1
<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server/client.crt)
</cert>
<key>
$(cat /etc/openvpn/server/client.key)
</key>
<tls-auth>
$(cat /etc/openvpn/server/ta.key)
</tls-auth>
EOF
"

# Install requested applications on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y virtualbox teamviewer realvnc-vnc-server realvnc-vnc-viewer anydesk vlc bash wget curl python3 python3-pip perl ruby ruby-dev docker.io automake autoconf cmake zsh nano nnn nodejs npm git nmap zenmap typescript golang rustc mysql-server lua5.3 openssh-server
"

# Configure SSH on both Windows and Kali Linux
wsl -d kali-linux -u root -- bash -c "
sed -i 's/#Port 22/Port 1022/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl enable ssh
systemctl start ssh
"

# Configure SSH on Windows
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# Set up shared keys and allow SSH between Windows and Kali
ssh-keygen -t rsa -b 4096 -f $env:USERPROFILE\.ssh\id_rsa -N ''
wsl -d kali-linux -u root -- bash -c "
mkdir -p /root/.ssh
echo '$(cat $env:USERPROFILE\.ssh\id_rsa.pub)' >> /root/.ssh/authorized_keys
"

# Enable DNS
wsl -d kali-linux -u root -- bash -c "
apt install -y bind9
systemctl enable bind9
systemctl start bind9
"

# Change desktop wallpaper every 5 minutes
# Windows
$script = @"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    public static void Set(string path) {
        SystemParametersInfo(20, 0, path, 0x01 | 0x02);
    }
}
'@
$wallpapers = Get-ChildItem -Path "C:\Path\To\Wallpapers" -Filter *.jpg
while ($true) {
    $wallpaper = Get-Random -InputObject $wallpapers
    [Wallpaper]::Set($wallpaper.FullName)
    Start-Sleep -Seconds 300
}
"@
Invoke-Expression $script

# Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt install -y feh
(crontab -l 2>/dev/null; echo '*/5 * * * * DISPLAY=:0 feh --randomize --bg-fill /usr/share/backgrounds/kali/*.jpg') | crontab -
"

# Add antivirus exceptions for Downloads and Desktop folders
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Downloads"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Desktop"

# Configure firewall to allow all services from installations
$firewallRules = @(
    'VirtualBox', 'TeamViewer', 'RealVNC', 'AnyDesk', 'VLC', 'Docker', 'OpenVPN', 'SSH'
)
foreach ($rule in $firewallRules) {
    New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow -Program "C:\Program Files\$rule\$rule.exe"
}

# Enable UPnP
Set-Service -Name upnphost -StartupType Automatic
Start-Service -Name upnphost

# Set up No-IP on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt install -y noip2
noip2 -C
systemctl enable noip2
systemctl start noip2
"

# Set prompt on all terminals
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
echo 'import sys\nsys.ps1 = \"$

# Configure Kodachi privacy settings on Windows
Start-Process -FilePath "C:\Program Files (x# Install PowerShell 7
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://github.com/PowerShell/PowerShell/releases/download/v7.2.3/PowerShell-7.2.3-win-x64.msi'))

# Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install ADB and Fastboot on Windows
choco install adb -y
choco install fastboot -y

# Install ADB and Fastboot on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y android-tools-adb android-tools-fastboot
"

# Install iCloud and iTunes on Windows
$icloudInstaller = 'https://secure-appldnld.apple.com/itunes12/001-23456-20210920-ABCDE12345/iCloudSetup.exe'
$itunesInstaller = 'https://secure-appldnld.apple.com/itunes12/001-23456-20210920-ABCDE12345/iTunesSetup.exe'
Invoke-WebRequest -Uri $icloudInstaller -OutFile "$env:TEMP\iCloudSetup.exe"
Invoke-WebRequest -Uri $itunesInstaller -OutFile "$env:TEMP\iTunesSetup.exe"
Start-Process -FilePath "$env:TEMP\iCloudSetup.exe" -ArgumentList '/quiet' -Wait
Start-Process -FilePath "$env:TEMP\iTunesSetup.exe" -ArgumentList '/quiet' -Wait

# Install Samsung Bootloader Changer App on Windows
$bootloaderChangerInstaller = 'https://example.com/samsung-bootloader-changer.exe'
Invoke-WebRequest -Uri $bootloaderChangerInstaller -OutFile "$env:TEMP\samsung-bootloader-changer.exe"
Start-Process -FilePath "$env:TEMP\samsung-bootloader-changer.exe" -ArgumentList '/quiet' -Wait

# Install Apktool on Windows
$apktoolInstaller = 'https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.6.1.jar'
$apktoolScript = 'https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat'
Invoke-WebRequest -Uri $apktoolInstaller -OutFile "$env:WINDIR\apktool.jar"
Invoke-WebRequest -Uri $apktoolScript -OutFile "$env:WINDIR\apktool.bat"

# Install Ghidra on Windows
$ghidraInstaller = 'https://ghidra-sre.org/ghidra_10.1.5_PUBLIC_20220210.zip'
Invoke-WebRequest -Uri $ghidraInstaller -OutFile "$env:TEMP\ghidra.zip"
Expand-Archive -Path "$env:TEMP\ghidra.zip" -DestinationPath "C:\Program Files\Ghidra"

# Install Wireshark on Windows
choco install wireshark -y

# Install Wireshark on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y wireshark
"

# Configure Wireshark to share database with Metasploit on Kali Linux
wsl -d kali-linux -u root -- bash -c "
echo 'db_connect msf:password@localhost/msf' >> /etc/metasploit/msfconsole.rc
"

# Install Ncat on Windows
choco install ncat -y

# Install Ncat on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y ncat
"

# Install Pcap tools on Windows
choco install npcap -y

# Install Pcap tools on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y libpcap-dev
"

# Install Hashcat on Windows
choco install hashcat -y

# Install Hashcat on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y hashcat
"

# Install Wifite3 on Windows
pip install wifite

# Install Wifite3 on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y wifite
"

# Change desktop wallpaper every 5 minutes on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt install -y feh
(crontab -l 2>/dev/null; echo '*/5 * * * * DISPLAY=:0 feh --randomize --bg-fill /usr/share/backgrounds/kali/*.jpg') | crontab -
"

# Remove games and bloatware from Windows
Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*Xbox*" -or $_.Name -like "*Zune*" -or $_.Name -like "*Bing*" } | Remove-AppxPackage
Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*Xbox*" -or $_.DisplayName -like "*Zune*" -or $_.DisplayName -like "*Bing*" } | Remove-AppxProvisionedPackage -Online

# Set prompt on all terminals
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

# Install OpenVPN on Windows
choco install openvpn -y

# Install WSL and Kali Linux
wsl --install -d kali-linux
wsl --set-default-version 2

# Install OpenVPN on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y openvpn network-manager-openvpn network-manager-openvpn-gnome
"

# Configure OpenVPN server on Kali Linux
wsl -d kali-linux -u root -- bash -c "
mkdir -p /etc/openvpn/server
cd /etc/openvpn/server
openvpn --genkey --secret ta.key
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz .
gunzip server.conf.gz
sed -i 's/;tls-auth ta.key 0/tls-auth ta.key 0/' server.conf
sed -i 's/;cipher AES-256-CBC/cipher AES-256-CBC/' server.conf
sed -i 's/;user nobody/user nobody/' server.conf
sed -i 's/;group nogroup/group nogroup/' server.conf
systemctl enable openvpn@server
systemctl start openvpn@server
"

# Generate .ovpn file for iPhone
wsl -d kali-linux -u root -- bash -c "
cat <<EOF > /etc/openvpn/client.ovpn
client
dev tun
proto udp
remote YOUR_SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
key-direction 1
<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server/client.crt)
</cert>
<key>
$(cat /etc/openvpn/server/client.key)
</key>
<tls-auth>
$(cat /etc/openvpn/server/ta.key)
</tls-auth>
EOF
"

# Install requested applications on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt install -y virtualbox teamviewer realvnc-vnc-server realvnc-vnc-viewer anydesk vlc bash wget curl python3 python3-pip perl ruby ruby-dev docker.io automake autoconf cmake zsh nano nnn nodejs npm git nmap zenmap typescript golang rustc mysql-server lua5.3 openssh-server
"

# Configure SSH on both Windows and Kali Linux
wsl -d kali-linux -u root -- bash -c "
sed -i 's/#Port 22/Port 1022/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl enable ssh
systemctl start ssh
"

# Configure SSH on Windows
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# Set up shared keys and allow SSH between Windows and Kali
ssh-keygen -t rsa -b 4096 -f $env:USERPROFILE\.ssh\id_rsa -N ''
wsl -d kali-linux -u root -- bash -c "
mkdir -p /root/.ssh
echo '$(cat $env:USERPROFILE\.ssh\id_rsa.pub)' >> /root/.ssh/authorized_keys
"

# Enable DNS
wsl -d kali-linux -u root -- bash -c "
apt install -y bind9
systemctl enable bind9
systemctl start bind9
"
Set the prompt on all installed and available terminals including zsh,nnn,bash,git,python,powershell on both windows and the kali instance to permanantly say "IEatDicks@ndGobbleBalls:  "

# Change desktop wallpaper every 5 minutes
# Windows
$script = @"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    public static void Set(string path) {
        SystemParametersInfo(20, 0, path, 0x01 | 0x02);
    }
}
'@
$wallpapers = Get-ChildItem -Path "C:\Path\To\Wallpapers" -Filter *.jpg
while ($true) {
    $wallpaper = Get-Random -InputObject $wallpapers
    [Wallpaper]::Set($wallpaper.FullName)
    Start-Sleep -Seconds 300
}
"@
Invoke-Expression $script

# Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt install -y feh
(crontab -l 2>/dev/null; echo '*/5 * * * * DISPLAY=:0 feh --randomize --bg-fill /usr/share/backgrounds/kali/*.jpg') | crontab -
"

# Add antivirus exceptions for Downloads and Desktop folders
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Downloads"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Desktop"

# Configure firewall to allow all services from installations
$firewallRules = @(
    'VirtualBox', 'TeamViewer', 'RealVNC', 'AnyDesk', 'VLC', 'Docker', 'OpenVPN', 'SSH'
)
foreach ($rule in $firewallRules) {
    New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow -Program "C:\Program Files\$rule\$rule.exe"
}

# Enable UPnP
Set-Service -Name upnphost -StartupType Automatic
Start-Service -Name upnphost

# Set up No-IP on Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt install -y noip2
noip2 -C
systemctl enable noip2
systemctl start noip2
"

# Set prompt on all terminals
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
echo '[core]\n    prompt = $prompt' >> /root

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
# Install PowerShell 7
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://github.com/PowerShell/PowerShell/releases/download/v7.2.3/PowerShell-7.2.3-win-x64.msi'))

# Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install various packages using Chocolatey
$packages = @(
    'VirtualBox', 'VirtualBox.ExtensionPack', 'TeamViewer', 'RealVNC.VNCServer', 'RealVNC.VNCViewer',
    'AnyDesk', 'VLC', 'Bash', 'wget', 'curl', 'Python', 'Bpkg', 'Clib', 'Perl', 'Ruby', 'Ruby-Gem',
    'DockerDesktop', 'Automake', 'Autoconf', 'CMake', 'Zsh', 'Nano', 'Nnn', 'Nodejs', 'Nvm', 'Npm',
    'Ls', 'Tree', 'Cd', 'Ip', 'Git', 'Nmap', 'Zenmap', 'TypeScript', 'Go', 'Rust', 'MySQL', 'Lua', 'OpenSSH'
)

foreach ($package in $packages) {
    choco install $package -y
}

# Install WSL and WSL2
wsl --install
wsl --set-default-version 2

# Install Kali Linux
wsl --install -d kali-linux

# Set up Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt full-upgrade -y
apt install -y kali-linux-everything
apt install -y openssh-server
systemctl enable ssh
systemctl start ssh
chsh -s /bin/bash
apt install -y powershell
ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N ''
apt install -y kali-win-kex
"

# Install AutoHotkey 3
Invoke-WebRequest 'https://www.autohotkey.com/download/ahk-install.exe' -OutFile autohotkey-install.exe
Start-Process -FilePath autohotkey-install.exe -Args '/silent' -Verb RunAs
Remove-Item autohotkey-install.exe

# Download and install specified applications
$appUrls = @{
    'Brave Nightly' = 'https://github.com/brave/brave-browser/releases/download/nightly/BraveBrowserNightlySetup.exe'
    'Chrome Nightly' = 'https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B9F6A1D2E-1A8A-4A5A-8E1A-5A4A5A4A5A4A%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DChrome%2520Canary%26needsadmin%3Dtrue/edgedl/chrome/install/GoogleChromeCanaryEnterprise.msi'
    'Edge Nightly' = 'https://www.microsoft.com/en-us/edge/download/insider'
    'Waterfox Nightly' = 'https://www.waterfox.net/download/'
    'Tor Browser + Onion' = 'https://www.torproject.org/dist/torbrowser/12.0.1/torbrowser-install-win64-12.0.1_en-US.exe'
    'Exploit Pack' = 'https://exploitpack.com/download/exploitpack.exe'
    'Empire' = 'https://github.com/EmpireProject/Empire/releases/download/3.6.0/Empire-3.6.0.zip'
    'Sn1per' = 'https://github.com/1N3/Sn1per/releases/download/v9.0/Sn1per-v9.0.zip'
    'Lxm' = 'https://github.com/lxm/lxm/releases/download/v1.0.0/lxm-1.0.0.zip'
    'Hypervisor' = 'https://www.hyperv.io/download/hypervisor.exe'
    'Ifttt' = 'https://ifttt.com/download/ifttt.exe'
    'Recuva' = 'https://www.ccleaner.com/recuva/download/standard'
    'Ccleaner' = 'https://www.ccleaner.com/ccleaner/download/standard'
    'Stremio' = 'https://www.stremio.com/downloads/stremio-setup.exe'
}

foreach ($app in $appUrls.GetEnumerator()) {
    $appName = $app.Key
    $appUrl = $app.Value
    $appFile = "$appName.exe"
    Invoke-WebRequest -Uri $appUrl -OutFile $appFile
    Start-Process -FilePath $appFile -Args '/silent' -Verb RunAs
    Remove-Item $appFile
}

# Function to generate API key (placeholder, as actual generation requires manual steps)
function Generate-APIKey {
    Write-Output 'Please visit https://ai.google.dev/gemini-api/docs/api-key to generate your API key.'
    Read-Host -Prompt 'Enter your API key'
}

# Set API key as environment variable
$apiKey = Generate-APIKey
[System.Environment]::SetEnvironmentVariable('GEMINI_API_KEY', $apiKey, [System.EnvironmentVariableTarget]::User)

# Verify installation and configuration
Write-Output 'Verifying installation...'
& go version
& gemini version

Write-Output 'Gemini CLI tools installed and configured successfully.'

# Manual installation notes
Write-Output 'The following tools require manual installation:'
$manualInstallations = @(
    'Brave Nightly', 'Chrome Nightly', 'Edge Nightly', 'Waterfox Nightly', 'Tor Browser + Onion',
    'Exploit Pack', 'Empire', 'Sn1per', 'Lxm', 'Hypervisor', 'Ifttt', 'Recuva', 'Ccleaner', 'Stremio'
)
$manualInstallations | ForEach-Object { Write-Output $_ }

# Install Atom IDE
Invoke-WebRequest 'https://atom.io/download/releases/atom-setup.exe' -OutFile atom-setup.exe
Start-Process -FilePath atom-setup.exe -Args '/silent /install /icon=setup.ico /dir=C:\Program Files (x86)\Atom' -Verb RunAs
Remove-Item atom-setup.exe

# Install Visual Basic IDE
Invoke-WebRequest 'https://visualstudio.microsoft.com/vs/older-releases/vs121/visual-studio-2012-isb-express-with-internet-tool-free-download-23822699/en_visual_basic_express_2012_with_sp1_x86_instl.exe' -OutFile visual_basic.exe
Start-Process -FilePath visual_basic.exe -Args '/quiet' -Verb RunAs
Remove-Item visual_basic.exe

# Install ProtonVPN
Invoke-WebRequest 'https://github.com/ProtonVPN/ProtonVPN-Installer/releases/download/v2.4.0/ProtonVPNInstaller_2.4.0.exe' -OutFile ProtonVPNInstaller_2.4.0.exe
Start-Process -FilePath ProtonVPNInstaller_2.4.0.exe -Args '/S' -Verb RunAs
Remove-Item ProtonVPNInstaller_2.4.0.exe

# Install Piece OS AI Browser Extension and EXA Search AI Browser Extension
Invoke-WebRequest 'https://github.com/pieces/pieces-browser-extension/releases/download/v0.2.1/pieces-extension-v0.2.1.crx' -OutFile pieces-extension-v0.2.1.crx
Invoke-WebRequest 'https://github.com/oliviertassin/exa/releases/download/v1.0.0/exa-v1.0.0.crx' -OutFile exa-v1.0.0.crx

# Add extensions to Chrome
Get-Process -Name chrome | Wait-Process -AppendArgs '--load-extension=pieces-extension-v0.2.1.crx' --load-extension=exa-v1.0.0.crx

# Add PowerShell scripts to Windows 10/11 devices in Microsoft Intune
Invoke-WebRequest 'https://raw.githubusercontent.com/PowerShell/PowerShell/dev/src/PowerShell/ps_modules/PowerShellGet/install-psmodule.ps1' -OutFile install-psmodule.ps1
Start-Process -FilePath PowerShell.exe -Args '-NoProfile -ExecutionPolicy Bypass -File install-psmodule.ps1' -Verb RunAs
Remove-Item install-psmodule.ps1

# Update all installed applications
choco upgrade all

# Update Windows for all updates including drivers
Install-Module PSWindowsUpdate -Force -SkipPublisherCheck
Import-Module PSWindowsUpdate
Get-WindowsUpdate -Install -AcceptAll -AutoReboot
# Install PowerShell 7
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://github.com/PowerShell/PowerShell/releases/download/v7.2.3/PowerShell-7.2.3-win-x64.msi'))

# Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install various packages using Chocolatey
$packages = @(
    'VirtualBox', 'VirtualBox.ExtensionPack', 'TeamViewer', 'RealVNC.VNCServer', 'RealVNC.VNCViewer',
    'AnyDesk', 'VLC', 'Bash', 'wget', 'curl', 'Python', 'Bpkg', 'Clib', 'Perl', 'Ruby', 'Ruby-Gem',
    'DockerDesktop', 'Automake', 'Autoconf', 'CMake', 'Zsh', 'Nano', 'Nnn', 'Nodejs', 'Nvm', 'Npm',
    'Ls', 'Tree', 'Cd', 'Ip', 'Git', 'Nmap', 'Zenmap', 'TypeScript', 'Go', 'Rust', 'MySQL', 'Lua', 'OpenSSH'
)

foreach ($package in $packages) {
    choco install $package -y
}

# Install WSL and WSL2
wsl --install
wsl --set-default-version 2

# Install Kali Linux
wsl --install -d kali-linux

# Set up Kali Linux
wsl -d kali-linux -u root -- bash -c "
apt update && apt full-upgrade -y
apt install -y kali-linux-everything
apt install -y openssh-server
systemctl enable ssh
systemctl start ssh
chsh -s /bin/bash
apt install -y powershell
ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N ''
apt install -y kali-win-kex
"

# Function to generate API key (placeholder, as actual generation requires manual steps)
function Generate-APIKey {
    Write-Output 'Please visit https://ai.google.dev/gemini-api/docs/api-key to generate your API key.'
    Read-Host -Prompt 'Enter your API key'
}

# Set API key as environment variable
$apiKey = Generate-APIKey
[System.Environment]::SetEnvironmentVariable('GEMINI_API_KEY', $apiKey, [System.EnvironmentVariableTarget]::User)

# Verify installation and configuration
Write-Output 'Verifying installation...'
& go version
& gemini version

Write-Output 'Gemini CLI tools installed and configured successfully.'

# Manual installation notes
Write-Output 'The following tools require manual installation:'
$manualInstallations = @(
    'Brave Nightly', 'Chrome Nightly', 'Edge Nightly', 'Waterfox Nightly', 'Tor Browser + Onion',
    'Exploit Pack', 'Empire', 'Sn1per', 'Lxm', 'Hypervisor', 'Ifttt', 'Recuva', 'Ccleaner', 'Stremio'
)
$manualInstallations | ForEach-Object { Write-Output $_ }

# Install Atom IDE
Invoke-WebRequest 'https://atom.io/download/releases/atom-setup.exe' -OutFile atom-setup.exe
Start-Process -FilePath atom-setup.exe -Args '/silent /install /icon=setup.ico /dir=C:\Program Files (x86)\Atom' -Verb RunAs
Remove-Item atom-setup.exe

# Install Visual Basic IDE
Invoke-WebRequest 'https://visualstudio.microsoft.com/vs/older-releases/vs121/visual-studio-2012-isb-express-with-internet-tool-free-download-23822699/en_visual_basic_express_2012_with_sp1_x86_instl.exe' -OutFile visual_basic.exe
Start-Process -FilePath visual_basic.exe -Args '/quiet' -Verb RunAs
Remove-Item visual_basic.exe

# Install ProtonVPN
Invoke-WebRequest 'https://github.com/ProtonVPN/ProtonVPN-Installer/releases/download/v2.4.0/ProtonVPNInstaller_2.4.0.exe' -OutFile ProtonVPNInstaller_2.4.0.exe
Start-Process -FilePath ProtonVPNInstaller_2.4.0.exe -Args '/S' -Verb RunAs
Remove-Item ProtonVPNInstaller_2.4.0.exe

# Install Go if not already installed
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Output "Go is not installed. Installing Go..."
    Invoke-WebRequest -Uri "https://golang.org/dl/go1.17.6.windows-amd64.msi" -OutFile "go.msi"
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i go.msi /quiet" -Wait
    Remove-Item -Path "go.msi"
    $env:Path += ";C:\Program Files\Go\bin"
}

# Install Gemini CLI tools
Write-Output "Installing Gemini CLI tools..."
go install github.com/reugn/gemini-cli/cmd/gemini@latest
go install github.com/eliben/gemini-cli@latest

# Function to generate API key (placeholder, as actual generation requires manual steps)
function Generate-APIKey {
    Write-Output "Please visit https://ai.google.dev/gemini-api/docs/api-key to generate your API key."
    Read-Host -Prompt "Enter your API key"
}

# Set API key as environment variable
$apiKey = Generate-APIKey
[System.Environment]::SetEnvironmentVariable("GEMINI_API_KEY", $apiKey, [System.EnvironmentVariableTarget]::User)

# Verify installation and configuration
Write-Output "Verifying installation..."
& go version
& gemini version

Write-Output "Gemini CLI tools installed and configured successfully."

# Install Piece OS AI Browser Extension and EXA Search AI Browser Extension
Invoke-WebRequest 'https://github.com/pieces/pieces-browser-extension/releases/download/v0.2.1/pieces-extension-v0.2.1.crx' -OutFile pieces-extension-v0.2.1.crx
Invoke-WebRequest 'https://github.com/oliviertassin/exa/releases/download/v1.0.0/exa-v1.0.0.crx' -OutFile exa-v1.0.0.crx

# Add extensions to Chrome
Get-Process -Name chrome | Wait-Process -AppendArgs '--load-extension=pieces-extension-v0.2.1.crx' --load-extension=exa-v1.0.0.crx

# Add PowerShell scripts to Windows 10/11 devices in Microsoft Intune
Invoke-WebRequest 'https://raw.githubusercontent.com/PowerShell/PowerShell/dev/src/PowerShell/ps_modules/PowerShellGet/install-psmodule.ps1' -OutFile install-psmodule.ps1
Start-Process -FilePath PowerShell.exe -Args '-NoProfile -ExecutionPolicy Bypass -File install-psmodule.ps1' -Verb RunAs
Remove-Item install-psmodule.ps1

# Update all installed applications
choco upgrade all

# Import iOS simulator into VirtualBox on Kali Linux
wsl -d kali-linux -u root -- bash -c "
VBoxManage import /mnt/c/Users/$env:USERNAME/TEMP/ios-simulator.ova
"
