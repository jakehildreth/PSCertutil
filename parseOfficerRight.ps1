function parseOfficerRight {
    param (
        $OfficerRight
    )

    $OfficerRightBlob = $OfficerRight | Select-String '^0\w{3}\s+' | ForEach-Object {                                                
        ($_.ToString().substring(4) -replace '.{16}$', '').Replace(' ', '').Replace("`t", '')
    }

    $OfficerRightByteArray = $OfficerRightBlob -replace '\s+', '' -split '(?<=\G.{2})' | Where-Object { $_ } | ForEach-Object {
        [System.Convert]::ToByte($_, 16)
    }

    # Everything from here down is stolen shamelessly from Vadims Podāns (https://sysadmins.lv)
    $SecurityDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($OfficerRightByteArray, 0)
    foreach ($commonAce in $SecurityDescriptor.DiscretionaryAcl) {
        # get ACE in binary form
        $aceBytes = New-Object byte[] -ArgumentList $commonAce.BinaryLength
        $commonAce.GetBinaryForm($aceBytes, 0)
        try {
            $CertificateManager = $commonAce.SecurityIdentifier.translate([Security.Principal.NTAccount]).Value
        } catch {
            $CertificateManager = $commonAce.SecurityIdentifier.Value
        }
        # set offset to application-specific data by skipping ACE header and
        # Officer's SID
        $offset = $commonAce.BinaryLength - $commonAce.OpaqueLength
        $SidCount = [BitConverter]::ToUInt32($aceBytes[$offset..($offset + 3)], 0)
        # initialize array to store array of securable principals
        $CanApproveRequestsFor = @()
        # perform this task only if SID count > 0.
        if ($SidCount -gt 0) {
            # exclude ACE header and trustee SID
            $SidStartOffset = $offset + 4
            # loop over a sequence of SIDs
            for ($i = 0; $i -lt $SidCount; $i++) {
                # calculate SID length
                $SidLength = if ($aceBytes[$SidStartOffset + 1] -lt 1) {
                    12
                } else {
                    12 + ($aceBytes[$SidStartOffset + 1] - 1) * 4
                }
                # extract SID bytes
                [Byte[]]$SidBytes = $aceBytes[$SidStartOffset..($SidStartOffset + $SidLength - 1)]
                # add resolved SID to an array of securable principals:
                $SID = New-Object Security.Principal.SecurityIdentifier $SidBytes, 0
                $CanApproveRequestsFor += $SID.translate([Security.Principal.NTAccount]).Value
                # move offset over current SID to a next one (if exist)
                $SidStartOffset += $SidLength
            }
        }
        $TemplateStartOffset = $SidStartOffset
        # Template is optional.
        $oid = $null
        if ($TemplateStartOffset -lt $aceBytes.Length) {
            $Template = [Text.Encoding]::Unicode.GetString($aceBytes[$TemplateStartOffset..($aceBytes.Length - 1)])
            # get common/friendly name of the template
            $oid = [Security.Cryptography.Oid]$Template
        }
        # prepare fake/simplified ACE object
        [PSCustomObject]@{
            CertificateManager    = $CertificateManager
            AceType               = $commonAce.AceQualifier
            CanApproveRequestsFor = $CanApproveRequestsFor
            Template              = if ($oid) {
                if ([string]::IsNullOrEmpty($oid.FriendlyName)) { $oid.Value } else { $oid.FriendlyName }
            } else {
                "<Any>"
            }
        }
    }
}