# Read-only diagnostic collector for the GTA III 1.1 Steam executable.
# It captures only the executable's .text section after Steam has loaded the game.
# Do not commit or publicly distribute the resulting dump.

param(
    [int]$TargetProcessId = 0,
    [string]$OutputDirectory = $env:TEMP
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# These values were read from the PE section headers of the supplied gta3.exe.
$expectedExeSha256 = '9B1DDAFADEE27DCA2970159BE497C9A851061711EC79EC319340A1A35C0DAA28'
$textRva = 0x1000
$textLength = 0x1F2770
$textFileOffset = 0x1000

$candidates = @(Get-Process -Name 'gta3' -ErrorAction SilentlyContinue)
if ($TargetProcessId -ne 0) {
    $candidates = @($candidates | Where-Object { $_.Id -eq $TargetProcessId })
}
if ($candidates.Count -ne 1) {
    throw "Expected one running gta3.exe process (found $($candidates.Count)). Start the game, reach the main menu and retry; use -TargetProcessId if necessary."
}

$gameProcess = $candidates[0]
$executablePath = $gameProcess.MainModule.FileName
$actualExeSha256 = (Get-FileHash -LiteralPath $executablePath -Algorithm SHA256).Hash
if ($actualExeSha256 -ne $expectedExeSha256) {
    throw "The running gta3.exe does not match the supplied Steam 1.1 executable (SHA256: $actualExeSha256). Stop; its section layout may differ."
}

if (-not ('Gta3ReadOnlyMemory' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class Gta3ReadOnlyMemory
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadProcessMemory(IntPtr process, IntPtr address,
        [Out] byte[] destination, UIntPtr size, out UIntPtr bytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
}

# PROCESS_VM_READ (0x10) | PROCESS_QUERY_INFORMATION (0x400).
# No permission to modify, suspend or inject anything into the game.
$processHandle = [Gta3ReadOnlyMemory]::OpenProcess(0x410, $false, $gameProcess.Id)
if ($processHandle -eq [IntPtr]::Zero) {
    $win32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "Could not open gta3.exe for read-only access (Win32 error $win32Error). Try running PowerShell at the same privilege level as the game."
}

try {
    $baseAddress = $gameProcess.MainModule.BaseAddress.ToInt64()
    $textAddress = [IntPtr]($baseAddress + $textRva)
    $textBytes = New-Object byte[] $textLength
    $readCount = [UIntPtr]::Zero

    $success = [Gta3ReadOnlyMemory]::ReadProcessMemory(
        $processHandle, $textAddress, $textBytes, [UIntPtr]$textLength, [ref]$readCount)
    if (-not $success -or $readCount.ToUInt64() -ne $textLength) {
        $win32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Could not read the complete .text section (Win32 error $win32Error; read $($readCount.ToUInt64()) bytes)."
    }
}
finally {
    [void][Gta3ReadOnlyMemory]::CloseHandle($processHandle)
}

# The disk .text section uses Steam's encrypted representation. Refuse to
# upload an unchanged copy; it does not help build an address translation map.
$diskBytes = [IO.File]::ReadAllBytes($executablePath)
$differentBytes = 0
for ($i = 0; $i -lt 1024; $i++) {
    if ($textBytes[$i] -ne $diskBytes[$textFileOffset + $i]) {
        $differentBytes++
    }
}
if ($differentBytes -eq 0) {
    throw 'The running code appears identical to the encrypted executable on disk. Reach the main menu and retry before sending a capture.'
}

if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    throw "Output directory does not exist: $OutputDirectory"
}
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$baseFilename = "gta3_steam11_text_$timestamp"
$binaryPath = Join-Path $OutputDirectory "$baseFilename.bin"
$archivePath = Join-Path $OutputDirectory "$baseFilename.zip"

[IO.File]::WriteAllBytes($binaryPath, $textBytes)
Compress-Archive -LiteralPath $binaryPath -DestinationPath $archivePath

Write-Host 'Read-only GTA III code capture complete.'
Write-Host "Text RVA: 0x$($textRva.ToString('X'))"
Write-Host "Bytes captured: $textLength"
Write-Host "Archive: $archivePath"
Write-Host 'Share the ZIP privately for analysis. Do not upload it to a public GitHub repository.'
