certutil -config $CAFullName -view Log csv | ConvertFrom-Csv |
    Where-Object { $_.'Serial Number' -ne 'EMPTY' } | ForEach-Object {
        "`n======================================"
        "Requester Name: $($_.'Requester Name')"
        "Certificate Effective Date: $($_.'Certificate Effective Date')"
        certutil -config $CAFullName -view -restrict "SerialNumber=$($_.'Serial Number')" |
            Select-String 'Subject Alternat' -Context 0, 3
        certutil -config $CAFullName -view -restrict "SerialNumber=$($_.'Serial Number')" |
            Select-String 'Request Attributes:' -Context 0, 2 -Exclude '"'
}