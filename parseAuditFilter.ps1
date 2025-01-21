function parseAuditFilter {
    param (
        $CertutilAudit
    )
    try {
        [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = ' | Select-String '\('
        [int]$AuditFilter = $AuditFilter.split('(')[1].split(')')[0]
    } catch {
        try {
            [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = '
            [int]$AuditFilter = $AuditFilter.split('=')[1].trim()
        } catch {
            [int]$AuditFilter = $null
        }
    }
    [pscustomobject]@{
        AuditFilter = $AuditFilter
    }
}