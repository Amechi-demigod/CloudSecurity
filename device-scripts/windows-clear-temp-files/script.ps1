# Deletes old temporary files. Parameters (validated against the signed manifest
# by the agent) arrive as environment variables only.
$ErrorActionPreference = 'Continue'
$days = [int]$env:CNAPP_PARAM_OLDER_THAN_DAYS
$scope = $env:CNAPP_PARAM_SCOPE
$dryRun = $env:CNAPP_PARAM_DRY_RUN -eq 'true'
if ($days -lt 1 -or $scope -notin @('system', 'users', 'all')) { Write-Error 'invalid parameters'; exit 64 }

$roots = @()
if ($scope -in @('system', 'all')) { $roots += Join-Path $env:SystemRoot 'Temp' }
if ($scope -in @('users', 'all')) {
    $profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath }
    foreach ($p in $profiles) {
        $t = Join-Path $p.LocalPath 'AppData\Local\Temp'
        if (Test-Path -LiteralPath $t) { $roots += $t }
    }
}
$cutoff = (Get-Date).AddDays(-$days)
$files = 0; $bytes = 0; $failed = 0
foreach ($root in $roots) {
    # -Force includes hidden files; reparse points are not followed.
    Get-ChildItem -LiteralPath $root -Recurse -Force -File -Attributes !ReparsePoint -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        ForEach-Object {
            if ($dryRun) { $files++; $bytes += $_.Length; return }
            try {
                $len = $_.Length
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                $files++; $bytes += $len
            } catch { $failed++ }
        }
}
$verb = if ($dryRun) { 'Would delete' } else { 'Deleted' }
Write-Output ("{0} {1} file(s), {2:N1} MB older than {3} day(s) in {4} folder(s); {5} skipped (in use or access denied)." -f `
    $verb, $files, ($bytes / 1MB), $days, $roots.Count, $failed)
$roots | ForEach-Object { Write-Output "  $_" }
