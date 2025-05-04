function Convert-EnrollmentAgentBlobToByteArray {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $EnrollmentAgentBlob
    )

    # Remove whitespace and split into byte array
    return $EnrollmentAgentBlob -replace '\s+', '' -split '(?<=\G.{2})' | Where-Object { $_ } | ForEach-Object {
        [System.Convert]::ToByte($_, 16)
    }
}