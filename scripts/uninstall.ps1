$ErrorActionPreference = 'Stop'

$InstallDirectory = Join-Path $env:LOCALAPPDATA 'cryptum'

if (Test-Path $InstallDirectory) {
    Remove-Item -Recurse -Force -Path $InstallDirectory
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not [string]::IsNullOrEmpty($userPath)) {
    $entries = $userPath.Split(';') | Where-Object { $_ -ne $InstallDirectory -and $_ -ne '' }
    [Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'User')
}

Write-Output 'cryptum removed'
