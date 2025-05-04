function parseCAAdministrator {
    param (
        $CAAdministrator
    )

    [array] $CAAdministratorCollection = $CAAdministrator | ForEach-Object {
        if ($_ -match '^.*Allow.*CA Administrator.*?\s+([^\s\\]+\\.+)$') {
            [PSCustomObject]@{
                CAAdministrator = $matches[1]
            }
        }
    }

    $CAAdministratorCollection
}