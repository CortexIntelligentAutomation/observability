$currentPath = Split-Path $MyInvocation.MyCommand.Path -Parent
Set-Location $currentPath

$exe = Join-Path $currentPath "loki-windows-amd64.exe"
$cfg = '"""{0}"""' -f (Join-Path $currentPath "loki-local-config.yaml") # path wrapped in quotes in case of spaces
$logs = Join-Path $currentPath "logs.txt"

.\nssm.exe install Loki $exe --config.file=$cfg
.\nssm.exe set Loki AppStderr $logs
.\nssm.exe set Loki AppStdout $logs
.\nssm.exe set Loki AppRotateFiles 1
.\nssm.exe set Loki AppRotateOnline 1
.\nssm.exe set Loki AppRotateSeconds 86400
.\nssm.exe set Loki AppRotateBytes 104857600
.\nssm.exe set Loki Start SERVICE_AUTO_START