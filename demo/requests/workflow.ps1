param([string]$BaseUrl = 'http://localhost:8000')
$ErrorActionPreference = 'Stop'
$apiKey = if ($env:NETLENS_API_KEY) { $env:NETLENS_API_KEY } else { 'change-me-local-only' }
$headers = @{ 'X-API-Key' = $apiKey }
$capture = curl.exe --fail-with-body -s -H "X-API-Key: $apiKey" -F 'file=@demo/captures/dns_failure.pcap' "$BaseUrl/v1/captures" | ConvertFrom-Json
$jobHeaders = @{ 'X-API-Key' = $apiKey; 'Idempotency-Key' = "demo-$($capture.id)" }
$analysis = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/analyses" -Headers $jobHeaders -ContentType 'application/json' -Body (@{capture_id=$capture.id} | ConvertTo-Json)
$deadline = (Get-Date).AddMinutes(2)
do {
    Start-Sleep -Milliseconds 250
    $analysis = Invoke-RestMethod -Uri "$BaseUrl$($analysis.status_url)" -Headers $headers
    if ((Get-Date) -gt $deadline) { throw 'Analysis polling timed out' }
} while ($analysis.status -in @('queued', 'running'))
if ($analysis.status -ne 'succeeded') { throw $analysis.error_code }
Invoke-RestMethod -Uri "$BaseUrl/v1/analyses/$($analysis.id)/findings" -Headers $headers | ConvertTo-Json -Depth 10
$report = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/analyses/$($analysis.id)/reports" -Headers $headers -ContentType 'application/json' -Body '{"provider":"mock"}'
$deadline = (Get-Date).AddMinutes(2)
do {
    Start-Sleep -Milliseconds 250
    $report = Invoke-RestMethod -Uri "$BaseUrl$($report.status_url)" -Headers $headers
    if ((Get-Date) -gt $deadline) { throw 'Report polling timed out' }
} while ($report.status -in @('queued', 'running'))
if ($report.status -ne 'succeeded') { throw $report.error_code }
$report | ConvertTo-Json -Depth 10
Invoke-RestMethod -Method Delete -Uri "$BaseUrl/v1/captures/$($capture.id)" -Headers $headers
