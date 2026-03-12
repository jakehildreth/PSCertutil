function parseLog {
    param (
        $Log
    )

    $logObject = $Log | ConvertFrom-Csv

    $logObject
}