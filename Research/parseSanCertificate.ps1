function parseSanCertificate {
    param(
        $SanCertificate
    )

    $SanCertificate

    # $SanObject = $SanCertificate | ConvertFrom-Csv

    # $SanObject

    # $SanObject | ForEach-Object {
    #     # Extract just the caller name
    #     $callerName = ($_ | Select-String 'Caller Name: "(.+)"').Matches[0].Groups[1].Value

    #     # Extract just the base64 data (skip headers/labels)
    #     $base64Lines = $_ | Where-Object { $_ -match '^[A-Za-z0-9+/=]+$' }
    #     $base64String = $base64Lines -join ''

    #     # Convert to byte array and create certificate object
    #     $certBytes = [Convert]::FromBase64String($base64String)
    #     $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)

    #     # Get the SAN extension
    #     $sanExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }

    #     # Decode the SAN
    #     $asnData = [System.Security.Cryptography.AsnEncodedData]::new($sanExtension.Oid, $sanExtension.RawData)
    #     try {
    #         $san = ($asnData.Format($true) | Select-String 'Principal Name=(.+)') |
    #             Select-Object -ExpandProperty Matches |
    #             Select-Object -ExpandProperty Groups -Skip 1 |
    #             Select-Object -ExpandProperty Value
    #         #.Matches[0].Groups[1].Value
    #     } catch {
    #         Write-Error 'Eff it, I am done.'
    #     }

    #     # Create an object to send to the pipeline
    #     [PSCustomObject]@{
    #         CallerName  = $callerName
    #         SAN         = $san
    #         Certificate = $cert
    #     }
    # }
}