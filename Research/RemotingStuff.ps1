$ComputerName = Read-Host 'Enter the Computer Name'
$params = @{
    ComputerName = $ComputerName
}

try {
    if (Test-WSMan @params -UseSSL) {
        Write-Host "INFO: SSL Enabled for PSRemoting on $($params.ComputerName)" -ForegroundColor Cyan
        $params.UseSSL = $true
    }
} catch {
    # Parse the WSManFault XML from the exception message
    if ($_.Exception.Message -match '<f:WSManFault.*?Code="(\d+)"') {
        $errorCode = $matches[1]
        
        switch ($errorCode) {
            '2150859193' {
                Write-Warning "Cannot resolve hostname: $ComputerName"
                return
            }
            '2150858770' {
                # Try without SSL
                try {
                    Test-WSMan @params | Out-Null
                    Write-Host "INFO: PSRemoting is available without SSL" -ForegroundColor Cyan
                } catch {
                    Write-Warning "PSRemoting is not available on $ComputerName"
                }
            }
            default {
                Write-Warning "Unexpected WS-Management error (Code: $errorCode)"
            }
        }
    } else {
        Write-Warning "Unknown error: $($_.Exception.Message)"
    }
}

$params.Credential = New-Credential -User (Read-Host 'Enter username in DOMAIN\username format')

