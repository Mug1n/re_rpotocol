param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$TestTargets = @("experiments/M01/tests/test_run.py")
)

# The host has an incorrect machine-level PYTHONHOME.  Scope the correction to
# this PowerShell process so project commands use the interpreter selected by PATH.
$pythonExe = (Get-Command python -ErrorAction Stop).Source
$env:PYTHONHOME = Split-Path -Parent $pythonExe
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue

# Wireshark is optional. Prefer a PATH installation, otherwise inspect the
# standard Start-menu shortcut so non-default installation directories work.
if (-not (Get-Command tshark -ErrorAction SilentlyContinue)) {
    $shortcutPath = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Wireshark.lnk'
    if (Test-Path -LiteralPath $shortcutPath) {
        $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
        if ($shortcut.TargetPath -and (Test-Path -LiteralPath $shortcut.TargetPath)) {
            $candidate = Split-Path -Parent $shortcut.TargetPath
            if ((Test-Path -LiteralPath (Join-Path $candidate 'tshark.exe')) -and (Test-Path -LiteralPath (Join-Path $candidate 'capinfos.exe'))) {
                $env:WIRESHARK_HOME = $candidate
            }
        }
    }
}

& $pythonExe -m unittest @TestTargets -v
exit $LASTEXITCODE

