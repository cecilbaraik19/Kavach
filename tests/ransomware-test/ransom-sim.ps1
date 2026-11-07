# Kavach ransomware protection test - SAFE
# It only writes random junk into a NEW folder "Kavach-Ransom-Test" in Documents
# and changes one of Kavach's own bait files. None of your real files are touched.
$docs = [Environment]::GetFolderPath('MyDocuments')
$test = Join-Path $docs 'Kavach-Ransom-Test'
New-Item -ItemType Directory -Force -Path $test | Out-Null
Write-Host "Fake ransomware test is running... (Kavach should stop this window within a few seconds)"

$bait = Get-ChildItem -LiteralPath $docs -Force -Filter '!!!Kavach-Bait*' -ErrorAction SilentlyContinue | Select-Object -First 1
$junk = New-Object byte[] (1MB)
(New-Object Random).NextBytes($junk)
$end = (Get-Date).AddSeconds(30)
$i = 0
while ((Get-Date) -lt $end) {
    [IO.File]::WriteAllBytes((Join-Path $test ("file$($i % 20).locked")), $junk)
    if ($i -eq 15) {
        if ($bait) {
            Write-Host "Touching bait file: $($bait.Name)"
            [IO.File]::AppendAllText($bait.FullName, 'ENCRYPTED-BY-TEST')
        } else {
            Write-Host "No bait file found in Documents - is Ransomware protection turned on?"
        }
    }
    $i++
    Start-Sleep -Milliseconds 100
}
Write-Host ""
Write-Host "TEST FAILED: Kavach did not stop this program. Press Enter to close."
Read-Host
