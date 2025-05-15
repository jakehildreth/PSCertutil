function parseDisableExtensionList {
    param (
        $DisableExtensionList
    )

    [array]$DisableExtensionListCollection = $DisableExtensionList | ForEach-Object {
        if ($_.ToString() -match '^\s+\d+: (.*)$') {
            [PSCustomObject]@{
                DisabledExtension = $matches[1]
            }
        }
    }

    $DisableExtensionListCollection
}