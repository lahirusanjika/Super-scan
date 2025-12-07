
$ErrorActionPreference = "Stop"

# Check Go
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Go is not installed or not in PATH."
}

Write-Host "Creating test secrets file..."
@"
AWS_KEY=AKIAIOSFODNN7EXAMPLE
NPM_TOKEN=npm_abcdef1234567890
STRIPE_KEY=sk_live_1234567890abcdef
SLACK_TOKEN=xoxb-1234567890-1234567890-abcdef
PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----
GOOGLE_KEY=AIzaSyD-1234567890abcdef
"@ | Out-File -Encoding utf8 test_full_secrets.txt

Write-Host "1. Building Project..." -ForegroundColor Cyan
go mod tidy
go build -o superscan.exe ./cmd/superscan
if (-not (Test-Path "superscan.exe")) {
    Write-Error "Build failed."
}
Write-Host "Build Success." -ForegroundColor Green

Write-Host "`n2. Testing Text Output..." -ForegroundColor Cyan
$textOut = .\superscan.exe test_full_secrets.txt
if ($textOut -match "AKIAIOSFODNN7EXAMPLE" -and $textOut -match "npm_") {
    Write-Host "Text Output Verified." -ForegroundColor Green
} else {
    Write-Error "Text Output failed to find secrets."
}

Write-Host "`n3. Testing JSON Output..." -ForegroundColor Cyan
$jsonOut = .\superscan.exe --json test_full_secrets.txt | ConvertFrom-Json
if ($jsonOut.findings.Count -gt 5) {
    Write-Host "JSON Output Verified ($($jsonOut.findings.Count) findings)." -ForegroundColor Green
} else {
    Write-Error "JSON Output seems incomplete."
}

Write-Host "`n4. Testing SARIF Output..." -ForegroundColor Cyan
$sarifOut = .\superscan.exe --sarif test_full_secrets.txt | ConvertFrom-Json
if ($sarifOut.runs[0].results.Count -gt 0) {
    Write-Host "SARIF Output Verified." -ForegroundColor Green
} else {
    Write-Error "SARIF Output failed."
}

Write-Host "`n5. Testing Baseline..." -ForegroundColor Cyan
# Create baseline
.\superscan.exe --baseline-create --baseline test_baseline.json test_full_secrets.txt
if (Test-Path "test_baseline.json") {
    Write-Host "Baseline Created." -ForegroundColor Green
} else {
    Write-Error "Baseline creation failed."
}

# Use baseline (should find 0 new secrets)
$baselineOut = .\superscan.exe --baseline test_baseline.json --json test_full_secrets.txt | ConvertFrom-Json
if ($baselineOut.findings.Count -eq 0) {
    Write-Host "Baseline Usage Verified (0 new findings)." -ForegroundColor Green
} else {
    Write-Error "Baseline usage failed. Found $($baselineOut.findings.Count) findings (expected 0)."
}

Write-Host "`nAll System Checks Passed!" -ForegroundColor Green

Write-Host "Cleaning up..."
Remove-Item test_full_secrets.txt -ErrorAction SilentlyContinue
Remove-Item test_baseline.json -ErrorAction SilentlyContinue
