$currentPath = Split-Path $MyInvocation.MyCommand.Path -Parent
Set-Location $currentPath

$exe = Join-Path $currentPath "promtail-windows-amd64.exe"
$cfg = '"""{0}"""' -f (Join-Path $currentPath "promtail-local-config.yaml") # Path wrapped in quotes in case of spaces
$logs = Join-Path $currentPath "logs.txt"

.\nssm.exe install Promtail $exe --config.file=$cfg
.\nssm.exe set Promtail AppStderr $logs
.\nssm.exe set Promtail AppStdout $logs
.\nssm.exe set Promtail AppRotateFiles 1
.\nssm.exe set Promtail AppRotateOnline 1
.\nssm.exe set Promtail AppRotateSeconds 86400
.\nssm.exe set Promtail AppRotateBytes 104857600
.\nssm.exe set Promtail Start SERVICE_AUTO_START