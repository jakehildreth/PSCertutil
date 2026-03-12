# Reset everyting
$base64Lines = @()
$base64String = $null
$callerName = $null
$certBytes = $null
$sanExtension = $null
$asnData = $null

# Get the binary certificate output
$output = certutil -v -view -config $CAFullName  -restrict "REquestId=1" -out "Binary Certificate,Request.CallerName"

# Extract just the caller name
$callerName = ($output | Select-String 'Caller Name: "(.+)"').Matches[0].Groups[1].Value

# Extract just the base64 data (skip headers/labels)
$base64Lines = $output | Where-Object { $_ -match '^[A-Za-z0-9+/=]+$' }
$base64String = $base64Lines -join ''

# Convert to byte array and create certificate object
$certBytes = [Convert]::FromBase64String($base64String)
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)

# Get the SAN extension
$sanExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }

# Decode the SAN
$asnData = [System.Security.Cryptography.AsnEncodedData]::new($sanExtension.Oid, $sanExtension.RawData)
$san = ($asnData.Format($true) | Select-String 'Principal Name=(.+)').Matches[0].Groups[1].Value

# Create an object to send to the pipeline
[PSCustomObject]@{
    CallerName = $callerName
    SAN        = $san
    Certificate = $cert
}