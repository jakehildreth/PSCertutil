function parseAuditFilter {
    param (
        $CertutilAudit
    )
    # TODO: Translate AuditFilter to human-readable format
    try {
        [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = ' | Select-String '\('
        [int]$AuditFilter = $AuditFilter.split('(')[1].split(')')[0]
    } catch {
        try {
            [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = '
            [int]$AuditFilter = $AuditFilter.split('=')[1].trim()
        } catch {
            # Parse failure (e.g. certutil errored): emit nothing so callers see
            # a query failure, not a fabricated 0 that looks like "auditing disabled".
            return
        }
    }
    [pscustomobject]@{
        AuditFilter = $AuditFilter
    }
}