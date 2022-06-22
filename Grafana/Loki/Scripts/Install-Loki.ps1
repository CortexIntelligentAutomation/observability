$currentPath = Split-Path $MyInvocation.MyCommand.Path -Parent
Set-Location $currentPath

$exe = Join-Path $currentPath "loki-windows-amd64.exe"
$cfg = Join-Path $currentPath "loki-local-config.yaml"
$logs = Join-Path $currentPath "logs.txt"

.\nssm.exe install Loki $exe --config.file=$cfg
.\nssm.exe set Loki AppStderr $logs
.\nssm.exe set Loki AppStdout $logs
.\nssm.exe set Loki Start SERVICE_AUTO_START