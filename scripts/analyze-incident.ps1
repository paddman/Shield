param(
    [Parameter(Mandatory = $true)]
    [string]$IncidentId,

    [string]$BrainUrl = "http://127.0.0.1:8088",
    [string]$Tenant = "demo",
    [Parameter(Mandatory = $true)]
    [string]$ApiKey
)

$headers = @{
    "X-NTShield-Tenant" = $Tenant
    "X-NTShield-Api-Key" = $ApiKey
}

$uri = "$($BrainUrl.TrimEnd('/'))/v1/central/incidents/$([uri]::EscapeDataString($IncidentId))/analyze"
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers
$response | ConvertTo-Json -Depth 20
