function parseInterfaceFlags {
    param (
        $InterfaceFlags
    )

    [array]$InterfaceFlags | ForEach-Object {
        ($_.trim().split(' -- '))[0] | Select-String 'IF_' | Out-String
    }
}