#requires -Version 5.1
<#
.SYNOPSIS
Create or repair this project's desktop shortcut and its persistent icon.
.DESCRIPTION
Only the shortcut named 矿大校园网登录器.lnk is managed. Other applications,
including CumtLogin, and Windows startup settings are not changed. Override
DesktopDirectory, IconDirectory and BackupDirectory for an isolated smoke test.
#>
[CmdletBinding()]
param(
    [string]$Executable,
    [string]$IconPath,
    [string]$DesktopDirectory,
    [string]$IconDirectory,
    [string]$BackupDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectDirectory = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if (-not $Executable) { $Executable = Join-Path $projectDirectory '校园网登录器.exe' }
if (-not $IconPath) { $IconPath = Join-Path $projectDirectory 'assets\icon.ico' }
if (-not $DesktopDirectory) { $DesktopDirectory = [Environment]::GetFolderPath('Desktop') }
if (-not $IconDirectory) {
    $IconDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'CumtCampusLogin\icons'
}
if (-not $BackupDirectory) { $BackupDirectory = Join-Path $projectDirectory '.local\backups\desktop-shortcut' }

$executableItem = Get-Item -LiteralPath $Executable
$iconItem = Get-Item -LiteralPath $IconPath
if ($executableItem.PSIsContainer -or $executableItem.Extension -ine '.exe') {
    throw 'Executable must be an existing Windows EXE file.'
}
if ($iconItem.PSIsContainer -or $iconItem.Extension -ine '.ico') {
    throw 'IconPath must be an existing ICO file.'
}
$version = [string]$executableItem.VersionInfo.FileVersion
if ($version -notmatch '^\d+(\.\d+){1,3}$') {
    throw 'The executable has no valid application file version; build and verify it first.'
}
$iconBytes = [System.IO.File]::ReadAllBytes($iconItem.FullName)
if ($iconBytes.Length -lt 6 -or [BitConverter]::ToUInt16($iconBytes, 0) -ne 0 -or
        [BitConverter]::ToUInt16($iconBytes, 2) -ne 1 -or [BitConverter]::ToUInt16($iconBytes, 4) -eq 0) {
    throw 'IconPath does not contain a valid ICO header.'
}
$iconHash = (Get-FileHash -LiteralPath $iconItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$DesktopDirectory = [System.IO.Path]::GetFullPath($DesktopDirectory)
$IconDirectory = [System.IO.Path]::GetFullPath($IconDirectory)
$BackupDirectory = [System.IO.Path]::GetFullPath($BackupDirectory)
# Directory.CreateDirectory treats paths literally, including any brackets.
[void][System.IO.Directory]::CreateDirectory($DesktopDirectory)
[void][System.IO.Directory]::CreateDirectory($IconDirectory)
$persistentIcon = Join-Path $IconDirectory ('campus-v{0}-{1}.ico' -f $version, $iconHash.Substring(0, 12))
if (-not (Test-Path -LiteralPath $persistentIcon)) {
    Copy-Item -LiteralPath $iconItem.FullName -Destination $persistentIcon
}
if ((Get-FileHash -LiteralPath $persistentIcon -Algorithm SHA256).Hash.ToLowerInvariant() -ne $iconHash) {
    throw 'Persistent icon content does not match the source icon.'
}

$shortcutPath = Join-Path $DesktopDirectory '矿大校园网登录器.lnk'
$workingDirectory = $executableItem.DirectoryName
$expectedIcon = $persistentIcon + ',0'
$existed = Test-Path -LiteralPath $shortcutPath
$backupPath = $null
if ($existed) {
    if ((Get-Item -LiteralPath $shortcutPath).PSIsContainer) { throw 'Shortcut path is a directory.' }
    [void][System.IO.Directory]::CreateDirectory($BackupDirectory)
    $backupName = 'campus-shortcut-{0}-{1}.lnk' -f (Get-Date -Format 'yyyyMMddTHHmmssfff'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $backupPath = Join-Path $BackupDirectory $backupName
    Copy-Item -LiteralPath $shortcutPath -Destination $backupPath
}

$linkShell = $null
$shortcut = $null
$readback = $null
try {
    $linkShell = New-Object -ComObject WScript.Shell
    $shortcut = $linkShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $executableItem.FullName
    $shortcut.Arguments = ''
    $shortcut.WorkingDirectory = $workingDirectory
    $shortcut.IconLocation = $expectedIcon
    $shortcut.Description = '矿大校园网登录器 v' + $version + '（东门与日晷图标）'
    $shortcut.WindowStyle = 1
    $shortcut.Save()
    $readback = $linkShell.CreateShortcut($shortcutPath)
    if (-not [string]::Equals($readback.TargetPath, $executableItem.FullName, [StringComparison]::OrdinalIgnoreCase) -or
            $readback.Arguments -ne '' -or
            -not [string]::Equals($readback.WorkingDirectory, $workingDirectory, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($readback.IconLocation, $expectedIcon, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Shortcut read-back verification failed.'
    }
}
catch {
    if ($backupPath) {
        Copy-Item -LiteralPath $backupPath -Destination $shortcutPath -Force
    }
    elseif (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
        Remove-Item -LiteralPath $shortcutPath
    }
    throw
}
finally {
    foreach ($comObject in @($readback, $shortcut, $linkShell)) {
        if ($null -ne $comObject) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject) }
    }
}

if (-not ('CumtDesktopShortcut.NativeShell' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CumtDesktopShortcut {
    public static class NativeShell {
        [DllImport("shell32.dll")]
        public static extern void SHChangeNotify(uint eventId, uint flags, IntPtr item1, IntPtr item2);
    }
}
'@
}
function Send-ShortcutRefresh([string]$ItemPath, [uint32]$EventId) {
    $pointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($ItemPath)
    try {
        # SHCNF_PATHW | SHCNF_FLUSH: refresh only the specified path.
        [CumtDesktopShortcut.NativeShell]::SHChangeNotify($EventId, 0x1005, $pointer, [IntPtr]::Zero)
    }
    finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer) }
}
Send-ShortcutRefresh $persistentIcon 0x2000 # SHCNE_UPDATEITEM
if ($existed) { Send-ShortcutRefresh $shortcutPath 0x2000 }
else { Send-ShortcutRefresh $shortcutPath 0x0002 } # SHCNE_CREATE
Send-ShortcutRefresh $DesktopDirectory 0x1000 # SHCNE_UPDATEDIR

[pscustomobject][ordered]@{
    version = $version
    shortcut = $shortcutPath
    executable = $executableItem.FullName
    working_directory = $workingDirectory
    icon = $persistentIcon
    icon_sha256 = $iconHash
    backup = $backupPath
    shortcut_verified = $true
    icon_verified = $true
    shell_refresh_sent = $true
} | ConvertTo-Json -Compress
