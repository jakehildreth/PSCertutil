$Certificates=Get-ADObject "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$((get-addomain).DistinguishedName)" -Properties cAcertificate
Write-Host "Found $(([array]$Certificates.cAcertificate).count) certificates in NTAuth store"
ForEach ($Certificate in ($Certificates.cAcertificate|ForEach{[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_)}))
{
  Write-Host "`t $($certificate.Subject) [$($certificate.Issuer)] $(get-date $certificate.notbefore -format 'yyyy-MM-dd') - $(get-date $certificate.notafter -format 'yyyy-MM-dd')"
}