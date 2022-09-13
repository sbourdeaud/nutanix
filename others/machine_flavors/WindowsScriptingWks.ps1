#install chocolatey
Set-ExecutionPolicy Unrestricted -Force -Confirm:$false
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

#install scripting and programming languages
choco install -y powershell
choco install -y powershell-core
choco install -y python3

#install tools
choco install -y googlechrome
choco install -y notepadplusplus
choco install -y 7zip
choco install -y adobereader
choco install -y ditto
choco install -y git
choco install -y putty
choco install -y winscp
choco install -y conemu

#install vscode and extensions
choco install -y vscode
choco install -y vscode-python
choco install -y vscode-pull-request-github
choco install -y vscode-kubernetes-tools
choco install -u vscode-powershell
