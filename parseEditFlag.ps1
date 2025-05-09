function parseEditFlag {
    param (
        $EditFlag
    )

    [array]$EditFlagCollection = $EditFlag | ForEach-Object {
        $Flag = ($_.trim().split(' -- '))[0] | Select-String 'EDITF_'
        if ($null -ne $Flag) {
            if ($Flag -match '^\(EDITF_') {
                $Flag = $Flag.ToString().Substring(1)
                $Enabled = $false
            } else {
                $Enabled = $true
            }

            [PSCustomObject]@{
                EditFlag = $Flag
                Enabled  = $Enabled
            }
        }
    }

    $EditFlagCollection
}