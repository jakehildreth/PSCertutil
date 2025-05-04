function parseInterfaceFlags {
    param (
        $InterfaceFlags
    )
    # TODO - Figure out why disabled flags are not being parsed correctly.
    [array]$InterfaceFlagCollection = $InterfaceFlags | ForEach-Object {
        $Flag = ($_.trim().split(' -- '))[0] | Select-String 'IF_'
        if ($null -ne $Flag) {
            if ($Flag -match '^\(IF_') {
                $Flag = $Flag.ToString().Substring(1)
                $Enabled = $false
            } else {
                $Enabled = $true
            }

            [PSCustomObject]@{
                InterfaceFlag = $Flag
                Enabled       = $Enabled
            }
        }
    }

    $InterfaceFlagCollection
}