function parseCAAdministrator {
    param (
        $CAAdministrator
    )

    [array] $CAAdministratorCollection = $CAAdministrator | ForEach-Object {
        if ($_ -match 'CA Administrator' -and $_ -split '\t' | Select-Object -Last 1) {
            [PSCustomObject]@{
                CAAdministrator = ($_ -split '\t' | Select-Object -Last 1).Trim()
            }
        }
    }

    $CAAdministratorCollection
}