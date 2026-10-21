# Lists the members of the local Administrators group (read-only).
# The group is looked up by its well-known SID, so this works in every language.
$ErrorActionPreference = 'Stop'
$group = Get-LocalGroup -SID 'S-1-5-32-544'
Write-Output "Group: $($group.Name) ($($group.SID))"
try {
    Get-LocalGroupMember -Group $group |
        Sort-Object Name |
        Format-Table -AutoSize Name, ObjectClass, PrincipalSource |
        Out-String -Width 200
} catch {
    # Get-LocalGroupMember fails on unresolvable (orphaned) SIDs; fall back to ADSI.
    Write-Output "Get-LocalGroupMember failed ($($_.Exception.Message)); using ADSI"
    $adsi = [ADSI]"WinNT://./$($group.Name),group"
    foreach ($m in $adsi.Invoke('Members')) {
        $m.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $m, $null) -replace '^WinNT://', ''
    }
}
