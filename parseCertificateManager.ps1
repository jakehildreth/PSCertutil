function parseCertificateManager {
    param (
        $CertificateManager
    )

    [array] $CertificateManagerCollection = $CertificateManager | ForEach-Object {
        if ($_ -match '^.*Allow.*Certificate Manager.*?\s+([^\s\\]+\\.+)$') {
            [PSCustomObject]@{
                CertificateManager = $matches[1]
            }
        }
    }

    $CertificateManagerCollection
}