function parseCertificateManager {
    param (
        $CertificateManager
    )

    [array] $CertificateManagerCollection = $CertificateManager | ForEach-Object {
        if ($_ -match 'Certificate Manager' -and $_ -split '\t' | Select-Object -Last 1) {
            [PSCustomObject]@{
                CertificateManager = ($_ -split '\t' | Select-Object -Last 1).Trim()
            }
        }
    }

    $CertificateManagerCollection
}