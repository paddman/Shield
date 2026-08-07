#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$InputPack,
    [Parameter(Mandatory)] [string]$OutputPack,
    [Parameter(Mandatory)] [string]$PrivateKeyPem
)

$ErrorActionPreference = 'Stop'
$pack = Get-Content -LiteralPath $InputPack -Raw | ConvertFrom-Json
$payload = [Text.Encoding]::UTF8.GetBytes([string]$pack.payloadJson)
$rsa = [Security.Cryptography.RSA]::Create()
$rsa.ImportFromPem((Get-Content -LiteralPath $PrivateKeyPem -Raw))
$hash = [Security.Cryptography.SHA256]::HashData($payload)
$pack.sha256 = [Convert]::ToHexString($hash).ToLowerInvariant()
$pack.signature = [Convert]::ToBase64String($rsa.SignData(
    $payload,
    [Security.Cryptography.HashAlgorithmName]::SHA256,
    [Security.Cryptography.RSASignaturePadding]::Pkcs1))
$pack.publishedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
$pack | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPack -Encoding utf8NoBOM
Write-Host "Signed protection pack $($pack.packId) v$($pack.version) -> $OutputPack"
