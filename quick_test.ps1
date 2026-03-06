$k = "varutri_shield_2026"
$url = "http://localhost:8080/api/chat"
$healthUrl = "http://localhost:8080/api/health"

Write-Host "--- CHECKING HEALTH ---"
try {
    $h = Invoke-RestMethod -Uri $healthUrl -Method Get -ErrorAction Stop
    $h | ConvertTo-Json
}
catch {
    Write-Host "Health Check Failed: $($_.Exception.Message)"
}

Write-Host "`n--- TESTING CHAT ---"
$body = @{
    sessionId = "mini-test"
    message   = @{ sender = "scammer"; text = "Call 9876543210 to claim lottery prize" }
} | ConvertTo-Json

try {
    $r = Invoke-RestMethod -Uri $url -Method Post -Body $body -Headers @{"x-api-key" = $k } -ContentType "application/json" -ErrorAction Stop
    Write-Host "Response:"
    $r.data | ConvertTo-Json -Depth 5
}
catch {
    Write-Host "Chat Request Failed: $($_.Exception.Message)"
    if ($_.Exception.Response) { Write-Host "Status: $($_.Exception.Response.StatusCode.value__)" }
    if ($_.Exception.Response) { 
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        Write-Host "Body: $($reader.ReadToEnd())"
    }
}
