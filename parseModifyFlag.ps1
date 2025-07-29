function parseModifyFlag {
    param (
        $ModifyFlag
    )

    if ($ModifyFlag -notcontains 'CertUtil: -setreg command completed successfully.') {
        $exception = $ModifyFlag -join ', '
        # TODO Start returning more specific error messages.
        [System.Management.Automation.ErrorRecord]::new($exception, 'CustomStringError', 'NotSpecified', $null)
    }
}