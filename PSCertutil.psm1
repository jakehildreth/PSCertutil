# Module created by Microsoft.PowerShell.Crescendo
# Version: 1.1.0
# Schema: https://aka.ms/PowerShell/Crescendo/Schemas/2022-06
# Generated at: 05/10/2025 06:23:48
class PowerShellCustomFunctionAttribute : System.Attribute {
    [bool]$RequiresElevation
    [string]$Source
    PowerShellCustomFunctionAttribute() { $this.RequiresElevation = $false; $this.Source = "Microsoft.PowerShell.Crescendo" }
    PowerShellCustomFunctionAttribute([bool]$rElevation) {
        $this.RequiresElevation = $rElevation
        $this.Source = "Microsoft.PowerShell.Crescendo"
    }
}

# Returns available errors
# Assumes that we are being called from within a script cmdlet when EmitAsError is used.
function Pop-CrescendoNativeError {
param ([switch]$EmitAsError)
    while ($__CrescendoNativeErrorQueue.Count -gt 0) {
        if ($EmitAsError) {
            $msg = $__CrescendoNativeErrorQueue.Dequeue()
            $er = [System.Management.Automation.ErrorRecord]::new([system.invalidoperationexception]::new($msg), $PSCmdlet.Name, "InvalidOperation", $msg)
            $PSCmdlet.WriteError($er)
        }
        else {
            $__CrescendoNativeErrorQueue.Dequeue()
        }
    }
}
# this is purposefully a filter rather than a function for streaming errors
filter Push-CrescendoNativeError {
    if ($_ -is [System.Management.Automation.ErrorRecord]) {
        $__CrescendoNativeErrorQueue.Enqueue($_)
    }
    else {
        $_
    }
}

function Get-PCDump
{
[PowerShellCustomFunctionAttribute(RequiresElevation=$False)]
[CmdletBinding()]

param(    )

BEGIN {
    $PSNativeCommandUseErrorActionPreference = $false
    $__CrescendoNativeErrorQueue = [System.Collections.Queue]::new()
    $__PARAMETERMAP = @{}
    $__outputHandlers = @{ Default = @{ StreamOutput = $true; Handler = { $input; Pop-CrescendoNativeError -EmitAsError } } }
}

PROCESS {
    $__boundParameters = $PSBoundParameters
    $__defaultValueParameters = $PSCmdlet.MyInvocation.MyCommand.Parameters.Values.Where({$_.Attributes.Where({$_.TypeId.Name -eq "PSDefaultValueAttribute"})}).Name
    $__defaultValueParameters.Where({ !$__boundParameters["$_"] }).ForEach({$__boundParameters["$_"] = get-variable -value $_})
    $__commandArgs = @()
    $MyInvocation.MyCommand.Parameters.Values.Where({$_.SwitchParameter -and $_.Name -notmatch "Debug|Whatif|Confirm|Verbose" -and ! $__boundParameters[$_.Name]}).ForEach({$__boundParameters[$_.Name] = [switch]::new($false)})
    if ($__boundParameters["Debug"]){wait-debugger}
    foreach ($paramName in $__boundParameters.Keys|
            Where-Object {!$__PARAMETERMAP[$_].ApplyToExecutable}|
            Where-Object {!$__PARAMETERMAP[$_].ExcludeAsArgument}|
            Sort-Object {$__PARAMETERMAP[$_].OriginalPosition}) {
        $value = $__boundParameters[$paramName]
        $param = $__PARAMETERMAP[$paramName]
        if ($param) {
            if ($value -is [switch]) {
                 if ($value.IsPresent) {
                     if ($param.OriginalName) { $__commandArgs += $param.OriginalName }
                 }
                 elseif ($param.DefaultMissingValue) { $__commandArgs += $param.DefaultMissingValue }
            }
            elseif ( $param.NoGap ) {
                # if a transform is specified, use it and the construction of the values is up to the transform
                if($param.ArgumentTransform -ne '$args') {
                    $transform = $param.ArgumentTransform
                    if($param.ArgumentTransformType -eq 'inline') {
                        $transform = [scriptblock]::Create($param.ArgumentTransform)
                    }
                    $__commandArgs += & $transform $value
                }
                else {
                    $pFmt = "{0}{1}"
                    # quote the strings if they have spaces
                    if($value -match "\s") { $pFmt = "{0}""{1}""" }
                    $__commandArgs += $pFmt -f $param.OriginalName, $value
                }
            }
            else {
                if($param.OriginalName) { $__commandArgs += $param.OriginalName }
                if($param.ArgumentTransformType -eq 'inline') {
                   $transform = [scriptblock]::Create($param.ArgumentTransform)
                }
                else {
                   $transform = $param.ArgumentTransform
                }
                $__commandArgs += & $transform $value
            }
        }
    }
    $__commandArgs = $__commandArgs | Where-Object {$_ -ne $null}
    if ($__boundParameters["Debug"]){wait-debugger}
    if ( $__boundParameters["Verbose"]) {
         Write-Verbose -Verbose -Message "C:\Windows\system32\certutil.exe"
         $__commandArgs | Write-Verbose -Verbose
    }
    $__handlerInfo = $__outputHandlers[$PSCmdlet.ParameterSetName]
    if (! $__handlerInfo ) {
        $__handlerInfo = $__outputHandlers["Default"] # Guaranteed to be present
    }
    $__handler = $__handlerInfo.Handler
    if ( $PSCmdlet.ShouldProcess("C:\Windows\system32\certutil.exe $__commandArgs")) {
    # check for the application and throw if it cannot be found
        if ( -not (Get-Command -ErrorAction Ignore "C:\Windows\system32\certutil.exe")) {
          throw "Cannot find executable 'C:\Windows\system32\certutil.exe'"
        }
        if ( $__handlerInfo.StreamOutput ) {
            if ( $null -eq $__handler ) {
                & "C:\Windows\system32\certutil.exe" $__commandArgs
            }
            else {
                & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError | & $__handler
            }
        }
        else {
            $result = & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError
            & $__handler $result
        }
    }
    # be sure to let the user know if there are any errors
    Pop-CrescendoNativeError -EmitAsError
  } # end PROCESS

<#
.SYNOPSIS

Verbs:
  -dump             -- Dump configuration information or file
  -dumpPFX          -- Dump PFX structure
  -asn              -- Parse ASN.1 file

  -decodehex        -- Decode hexadecimal-encoded file
  -decode           -- Decode Base64-encoded file
  -encode           -- Encode file to Base64

  -deny             -- Deny pending request
  -resubmit         -- Resubmit pending request
  -setattributes    -- Set attributes for pending request
  -setextension     -- Set extension for pending request
  -revoke           -- Revoke Certificate
  -isvalid          -- Display current certificate disposition

  -getconfig        -- Get default configuration string
  -ping             -- Ping Active Directory Certificate Services Request interface
  -pingadmin        -- Ping Active Directory Certificate Services Admin interface
  -CAInfo           -- Display CA Information
  -ca.cert          -- Retrieve the CA's certificate
  -ca.chain         -- Retrieve the CA's certificate chain
  -GetCRL           -- Get CRL
  -CRL              -- Publish new CRLs [or delta CRLs only]
  -shutdown         -- Shutdown Active Directory Certificate Services

  -installCert      -- Install Certification Authority certificate
  -renewCert        -- Renew Certification Authority certificate

  -schema           -- Dump Certificate Schema
  -view             -- Dump Certificate View
  -db               -- Dump Raw Database
  -deleterow        -- Delete server database row

  -backup           -- Backup Active Directory Certificate Services
  -backupDB         -- Backup Active Directory Certificate Services database
  -backupKey        -- Backup Active Directory Certificate Services certificate and private key
  -restore          -- Restore Active Directory Certificate Services
  -restoreDB        -- Restore Active Directory Certificate Services database
  -restoreKey       -- Restore Active Directory Certificate Services certificate and private key
  -importPFX        -- Import certificate and private key
  -dynamicfilelist  -- Display dynamic file List
  -databaselocations -- Display database locations
  -hashfile         -- Generate and display cryptographic hash over a file

  -store            -- Dump certificate store
  -enumstore        -- Enumerate certificate stores
  -addstore         -- Add certificate to store
  -delstore         -- Delete certificate from store
  -verifystore      -- Verify certificate in store
  -repairstore      -- Repair key association or update certificate properties or key security descriptor
  -viewstore        -- Dump certificate store
  -viewdelstore     -- Delete certificate from store
  -UI               -- invoke CryptUI
  -attest           -- Verify Key Attestation Request

  -dsPublish        -- Publish certificate or CRL to Active Directory

  -ADTemplate       -- Display AD templates
  -Template         -- Display Enrollment Policy templates
  -TemplateCAs      -- Display CAs for template
  -CATemplates      -- Display templates for CA
  -SetCASites       -- Manage Site Names for CAs
  -enrollmentServerURL -- Display, add or delete enrollment server URLs associated with a CA
  -ADCA             -- Display AD CAs
  -CA               -- Display Enrollment Policy CAs
  -Policy           -- Display Enrollment Policy
  -PolicyCache      -- Display or delete Enrollment Policy Cache entries
  -CredStore        -- Display, add or delete Credential Store entries
  -InstallDefaultTemplates -- Install default certificate templates
  -URLCache         -- Display or delete URL cache entries
  -pulse            -- Pulse autoenrollment event or NGC task
  -MachineInfo      -- Display Active Directory machine object information
  -DCInfo           -- Display domain controller information
  -EntInfo          -- Display enterprise information
  -TCAInfo          -- Display CA information
  -SCInfo           -- Display smart card information

  -SCRoots          -- Manage smart card root certificates

  -DeleteHelloContainer -- Delete Hello Logon container.  
     ** Users need to sign out after using this option for it to complete. **
  -verifykeys       -- Verify public/private key set
  -verify           -- Verify certificate, CRL or chain
  -verifyCTL        -- Verify AuthRoot or Disallowed Certificates CTL
  -syncWithWU       -- Sync with Windows Update
  -generateSSTFromWU -- Generate SST from Windows Update
  -generatePinRulesCTL -- Generate Pin Rules CTL
  -downloadOcsp     -- Download OCSP Responses and Write to Directory
  -generateHpkpHeader -- Generate HPKP header using certificates in specified file or directory
  -flushCache       -- Flush specified caches in selected process, such as, lsass.exe
  -addEccCurve      -- Add ECC Curve
  -deleteEccCurve   -- Delete ECC Curve
  -displayEccCurve  -- Display ECC Curve
  -sign             -- Re-sign CRL or certificate

  -vroot            -- Create/delete web virtual roots and file shares
  -vocsproot        -- Create/delete web virtual roots for OCSP web proxy
  -addEnrollmentServer -- Add an Enrollment Server application
  -deleteEnrollmentServer -- Delete an Enrollment Server application
  -addPolicyServer  -- Add a Policy Server application
  -deletePolicyServer -- Delete a Policy Server application
  -oid              -- Display ObjectId or set display name
  -error            -- Display error code message text
  -getreg           -- Display registry value
  -setreg           -- Set registry value
  -delreg           -- Delete registry value

  -ImportKMS        -- Import user keys and certificates into server database for key archival
  -ImportCert       -- Import a certificate file into the database
  -GetKey           -- Retrieve archived private key recovery blob, generate a recovery script,
      or recover archived keys
  -RecoverKey       -- Recover archived private key
  -MergePFX         -- Merge PFX files

  -add-chain        -- (-AddChain) Add certificate chain
  -add-pre-chain    -- (-AddPrechain) Add pre-certificate chain
  -get-sth          -- (-GetSTH) Get signed tree head
  -get-sth-consistency -- (-GetSTHConsistency) Get signed tree head changes
  -get-proof-by-hash -- (-GetProofByHash) Get proof by hash
  -get-entries      -- (-GetEntries) Get entries
  -get-roots        -- (-GetRoots) Get roots
  -get-entry-and-proof -- (-GetEntryAndProof) Get entry and proof
  -VerifyCT         -- Verify certificate SCT
  -?                -- Display this usage message


CertUtil -?              -- Display a verb list (command list)
CertUtil -dump -?        -- Display help text for the "dump" verb
CertUtil -v -?           -- Display all help text for all verbs

CertUtil: -? command completed successfully.

.DESCRIPTION See help for C:\Windows\system32\certutil.exe

#>
}


function Get-PCCAAdministrator
{
[PowerShellCustomFunctionAttribute(RequiresElevation=$False)]
[CmdletBinding()]

param(
[Parameter(Mandatory=$true,ParameterSetName='Default')]
[string]$CAFullName,
[Parameter(ParameterSetName='Default')]
[PSDefaultValue(Value="CA\Security")]
[string]$GetReg = "CA\Security"
    )

BEGIN {
    $PSNativeCommandUseErrorActionPreference = $false
    $__CrescendoNativeErrorQueue = [System.Collections.Queue]::new()
    $__PARAMETERMAP = @{
         CAFullName = @{
               OriginalName = '-config'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
         GetReg = @{
               OriginalName = '-getreg'
               OriginalPosition = '1'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
    }

    $__outputHandlers = @{
        Default = @{ StreamOutput = $False; Handler = 'parseCAAdministrator' }
    }
}

PROCESS {
    $__boundParameters = $PSBoundParameters
    $__defaultValueParameters = $PSCmdlet.MyInvocation.MyCommand.Parameters.Values.Where({$_.Attributes.Where({$_.TypeId.Name -eq "PSDefaultValueAttribute"})}).Name
    $__defaultValueParameters.Where({ !$__boundParameters["$_"] }).ForEach({$__boundParameters["$_"] = get-variable -value $_})
    $__commandArgs = @()
    $MyInvocation.MyCommand.Parameters.Values.Where({$_.SwitchParameter -and $_.Name -notmatch "Debug|Whatif|Confirm|Verbose" -and ! $__boundParameters[$_.Name]}).ForEach({$__boundParameters[$_.Name] = [switch]::new($false)})
    if ($__boundParameters["Debug"]){wait-debugger}
    foreach ($paramName in $__boundParameters.Keys|
            Where-Object {!$__PARAMETERMAP[$_].ApplyToExecutable}|
            Where-Object {!$__PARAMETERMAP[$_].ExcludeAsArgument}|
            Sort-Object {$__PARAMETERMAP[$_].OriginalPosition}) {
        $value = $__boundParameters[$paramName]
        $param = $__PARAMETERMAP[$paramName]
        if ($param) {
            if ($value -is [switch]) {
                 if ($value.IsPresent) {
                     if ($param.OriginalName) { $__commandArgs += $param.OriginalName }
                 }
                 elseif ($param.DefaultMissingValue) { $__commandArgs += $param.DefaultMissingValue }
            }
            elseif ( $param.NoGap ) {
                # if a transform is specified, use it and the construction of the values is up to the transform
                if($param.ArgumentTransform -ne '$args') {
                    $transform = $param.ArgumentTransform
                    if($param.ArgumentTransformType -eq 'inline') {
                        $transform = [scriptblock]::Create($param.ArgumentTransform)
                    }
                    $__commandArgs += & $transform $value
                }
                else {
                    $pFmt = "{0}{1}"
                    # quote the strings if they have spaces
                    if($value -match "\s") { $pFmt = "{0}""{1}""" }
                    $__commandArgs += $pFmt -f $param.OriginalName, $value
                }
            }
            else {
                if($param.OriginalName) { $__commandArgs += $param.OriginalName }
                if($param.ArgumentTransformType -eq 'inline') {
                   $transform = [scriptblock]::Create($param.ArgumentTransform)
                }
                else {
                   $transform = $param.ArgumentTransform
                }
                $__commandArgs += & $transform $value
            }
        }
    }
    $__commandArgs = $__commandArgs | Where-Object {$_ -ne $null}
    if ($__boundParameters["Debug"]){wait-debugger}
    if ( $__boundParameters["Verbose"]) {
         Write-Verbose -Verbose -Message "C:\Windows\system32\certutil.exe"
         $__commandArgs | Write-Verbose -Verbose
    }
    $__handlerInfo = $__outputHandlers[$PSCmdlet.ParameterSetName]
    if (! $__handlerInfo ) {
        $__handlerInfo = $__outputHandlers["Default"] # Guaranteed to be present
    }
    $__handler = $__handlerInfo.Handler
    if ( $PSCmdlet.ShouldProcess("C:\Windows\system32\certutil.exe $__commandArgs")) {
    # check for the application and throw if it cannot be found
        if ( -not (Get-Command -ErrorAction Ignore "C:\Windows\system32\certutil.exe")) {
          throw "Cannot find executable 'C:\Windows\system32\certutil.exe'"
        }
        if ( $__handlerInfo.StreamOutput ) {
            if ( $null -eq $__handler ) {
                & "C:\Windows\system32\certutil.exe" $__commandArgs
            }
            else {
                & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError | & $__handler
            }
        }
        else {
            $result = & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError
            & $__handler $result
        }
    }
    # be sure to let the user know if there are any errors
    Pop-CrescendoNativeError -EmitAsError
  } # end PROCESS

<#
.SYNOPSIS

Verbs:
  -dump             -- Dump configuration information or file
  -dumpPFX          -- Dump PFX structure
  -asn              -- Parse ASN.1 file

  -decodehex        -- Decode hexadecimal-encoded file
  -decode           -- Decode Base64-encoded file
  -encode           -- Encode file to Base64

  -deny             -- Deny pending request
  -resubmit         -- Resubmit pending request
  -setattributes    -- Set attributes for pending request
  -setextension     -- Set extension for pending request
  -revoke           -- Revoke Certificate
  -isvalid          -- Display current certificate disposition

  -getconfig        -- Get default configuration string
  -ping             -- Ping Active Directory Certificate Services Request interface
  -pingadmin        -- Ping Active Directory Certificate Services Admin interface
  -CAInfo           -- Display CA Information
  -ca.cert          -- Retrieve the CA's certificate
  -ca.chain         -- Retrieve the CA's certificate chain
  -GetCRL           -- Get CRL
  -CRL              -- Publish new CRLs [or delta CRLs only]
  -shutdown         -- Shutdown Active Directory Certificate Services

  -installCert      -- Install Certification Authority certificate
  -renewCert        -- Renew Certification Authority certificate

  -schema           -- Dump Certificate Schema
  -view             -- Dump Certificate View
  -db               -- Dump Raw Database
  -deleterow        -- Delete server database row

  -backup           -- Backup Active Directory Certificate Services
  -backupDB         -- Backup Active Directory Certificate Services database
  -backupKey        -- Backup Active Directory Certificate Services certificate and private key
  -restore          -- Restore Active Directory Certificate Services
  -restoreDB        -- Restore Active Directory Certificate Services database
  -restoreKey       -- Restore Active Directory Certificate Services certificate and private key
  -importPFX        -- Import certificate and private key
  -dynamicfilelist  -- Display dynamic file List
  -databaselocations -- Display database locations
  -hashfile         -- Generate and display cryptographic hash over a file

  -store            -- Dump certificate store
  -enumstore        -- Enumerate certificate stores
  -addstore         -- Add certificate to store
  -delstore         -- Delete certificate from store
  -verifystore      -- Verify certificate in store
  -repairstore      -- Repair key association or update certificate properties or key security descriptor
  -viewstore        -- Dump certificate store
  -viewdelstore     -- Delete certificate from store
  -UI               -- invoke CryptUI
  -attest           -- Verify Key Attestation Request

  -dsPublish        -- Publish certificate or CRL to Active Directory

  -ADTemplate       -- Display AD templates
  -Template         -- Display Enrollment Policy templates
  -TemplateCAs      -- Display CAs for template
  -CATemplates      -- Display templates for CA
  -SetCASites       -- Manage Site Names for CAs
  -enrollmentServerURL -- Display, add or delete enrollment server URLs associated with a CA
  -ADCA             -- Display AD CAs
  -CA               -- Display Enrollment Policy CAs
  -Policy           -- Display Enrollment Policy
  -PolicyCache      -- Display or delete Enrollment Policy Cache entries
  -CredStore        -- Display, add or delete Credential Store entries
  -InstallDefaultTemplates -- Install default certificate templates
  -URLCache         -- Display or delete URL cache entries
  -pulse            -- Pulse autoenrollment event or NGC task
  -MachineInfo      -- Display Active Directory machine object information
  -DCInfo           -- Display domain controller information
  -EntInfo          -- Display enterprise information
  -TCAInfo          -- Display CA information
  -SCInfo           -- Display smart card information

  -SCRoots          -- Manage smart card root certificates

  -DeleteHelloContainer -- Delete Hello Logon container.  
     ** Users need to sign out after using this option for it to complete. **
  -verifykeys       -- Verify public/private key set
  -verify           -- Verify certificate, CRL or chain
  -verifyCTL        -- Verify AuthRoot or Disallowed Certificates CTL
  -syncWithWU       -- Sync with Windows Update
  -generateSSTFromWU -- Generate SST from Windows Update
  -generatePinRulesCTL -- Generate Pin Rules CTL
  -downloadOcsp     -- Download OCSP Responses and Write to Directory
  -generateHpkpHeader -- Generate HPKP header using certificates in specified file or directory
  -flushCache       -- Flush specified caches in selected process, such as, lsass.exe
  -addEccCurve      -- Add ECC Curve
  -deleteEccCurve   -- Delete ECC Curve
  -displayEccCurve  -- Display ECC Curve
  -sign             -- Re-sign CRL or certificate

  -vroot            -- Create/delete web virtual roots and file shares
  -vocsproot        -- Create/delete web virtual roots for OCSP web proxy
  -addEnrollmentServer -- Add an Enrollment Server application
  -deleteEnrollmentServer -- Delete an Enrollment Server application
  -addPolicyServer  -- Add a Policy Server application
  -deletePolicyServer -- Delete a Policy Server application
  -oid              -- Display ObjectId or set display name
  -error            -- Display error code message text
  -getreg           -- Display registry value
  -setreg           -- Set registry value
  -delreg           -- Delete registry value

  -ImportKMS        -- Import user keys and certificates into server database for key archival
  -ImportCert       -- Import a certificate file into the database
  -GetKey           -- Retrieve archived private key recovery blob, generate a recovery script,
      or recover archived keys
  -RecoverKey       -- Recover archived private key
  -MergePFX         -- Merge PFX files

  -add-chain        -- (-AddChain) Add certificate chain
  -add-pre-chain    -- (-AddPrechain) Add pre-certificate chain
  -get-sth          -- (-GetSTH) Get signed tree head
  -get-sth-consistency -- (-GetSTHConsistency) Get signed tree head changes
  -get-proof-by-hash -- (-GetProofByHash) Get proof by hash
  -get-entries      -- (-GetEntries) Get entries
  -get-roots        -- (-GetRoots) Get roots
  -get-entry-and-proof -- (-GetEntryAndProof) Get entry and proof
  -VerifyCT         -- Verify certificate SCT
  -?                -- Display this usage message


CertUtil -?              -- Display a verb list (command list)
CertUtil -dump -?        -- Display help text for the "dump" verb
CertUtil -v -?           -- Display all help text for all verbs

CertUtil: -? command completed successfully.

.DESCRIPTION See help for C:\Windows\system32\certutil.exe

.PARAMETER CAFullName
Specify the Full Name of the Certificate Authority in the form 'FQDN\CA Name'


.PARAMETER GetReg
Specify Security



#>
}


function Get-PCCertificateManager
{
[PowerShellCustomFunctionAttribute(RequiresElevation=$False)]
[CmdletBinding()]

param(
[Parameter(Mandatory=$true,ParameterSetName='Default')]
[string]$CAFullName,
[Parameter(ParameterSetName='Default')]
[PSDefaultValue(Value="CA\Security")]
[string]$GetReg = "CA\Security"
    )

BEGIN {
    $PSNativeCommandUseErrorActionPreference = $false
    $__CrescendoNativeErrorQueue = [System.Collections.Queue]::new()
    $__PARAMETERMAP = @{
         CAFullName = @{
               OriginalName = '-config'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
         GetReg = @{
               OriginalName = '-getreg'
               OriginalPosition = '1'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
    }

    $__outputHandlers = @{
        Default = @{ StreamOutput = $False; Handler = 'parseCertificateManager' }
    }
}

PROCESS {
    $__boundParameters = $PSBoundParameters
    $__defaultValueParameters = $PSCmdlet.MyInvocation.MyCommand.Parameters.Values.Where({$_.Attributes.Where({$_.TypeId.Name -eq "PSDefaultValueAttribute"})}).Name
    $__defaultValueParameters.Where({ !$__boundParameters["$_"] }).ForEach({$__boundParameters["$_"] = get-variable -value $_})
    $__commandArgs = @()
    $MyInvocation.MyCommand.Parameters.Values.Where({$_.SwitchParameter -and $_.Name -notmatch "Debug|Whatif|Confirm|Verbose" -and ! $__boundParameters[$_.Name]}).ForEach({$__boundParameters[$_.Name] = [switch]::new($false)})
    if ($__boundParameters["Debug"]){wait-debugger}
    foreach ($paramName in $__boundParameters.Keys|
            Where-Object {!$__PARAMETERMAP[$_].ApplyToExecutable}|
            Where-Object {!$__PARAMETERMAP[$_].ExcludeAsArgument}|
            Sort-Object {$__PARAMETERMAP[$_].OriginalPosition}) {
        $value = $__boundParameters[$paramName]
        $param = $__PARAMETERMAP[$paramName]
        if ($param) {
            if ($value -is [switch]) {
                 if ($value.IsPresent) {
                     if ($param.OriginalName) { $__commandArgs += $param.OriginalName }
                 }
                 elseif ($param.DefaultMissingValue) { $__commandArgs += $param.DefaultMissingValue }
            }
            elseif ( $param.NoGap ) {
                # if a transform is specified, use it and the construction of the values is up to the transform
                if($param.ArgumentTransform -ne '$args') {
                    $transform = $param.ArgumentTransform
                    if($param.ArgumentTransformType -eq 'inline') {
                        $transform = [scriptblock]::Create($param.ArgumentTransform)
                    }
                    $__commandArgs += & $transform $value
                }
                else {
                    $pFmt = "{0}{1}"
                    # quote the strings if they have spaces
                    if($value -match "\s") { $pFmt = "{0}""{1}""" }
                    $__commandArgs += $pFmt -f $param.OriginalName, $value
                }
            }
            else {
                if($param.OriginalName) { $__commandArgs += $param.OriginalName }
                if($param.ArgumentTransformType -eq 'inline') {
                   $transform = [scriptblock]::Create($param.ArgumentTransform)
                }
                else {
                   $transform = $param.ArgumentTransform
                }
                $__commandArgs += & $transform $value
            }
        }
    }
    $__commandArgs = $__commandArgs | Where-Object {$_ -ne $null}
    if ($__boundParameters["Debug"]){wait-debugger}
    if ( $__boundParameters["Verbose"]) {
         Write-Verbose -Verbose -Message "C:\Windows\system32\certutil.exe"
         $__commandArgs | Write-Verbose -Verbose
    }
    $__handlerInfo = $__outputHandlers[$PSCmdlet.ParameterSetName]
    if (! $__handlerInfo ) {
        $__handlerInfo = $__outputHandlers["Default"] # Guaranteed to be present
    }
    $__handler = $__handlerInfo.Handler
    if ( $PSCmdlet.ShouldProcess("C:\Windows\system32\certutil.exe $__commandArgs")) {
    # check for the application and throw if it cannot be found
        if ( -not (Get-Command -ErrorAction Ignore "C:\Windows\system32\certutil.exe")) {
          throw "Cannot find executable 'C:\Windows\system32\certutil.exe'"
        }
        if ( $__handlerInfo.StreamOutput ) {
            if ( $null -eq $__handler ) {
                & "C:\Windows\system32\certutil.exe" $__commandArgs
            }
            else {
                & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError | & $__handler
            }
        }
        else {
            $result = & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError
            & $__handler $result
        }
    }
    # be sure to let the user know if there are any errors
    Pop-CrescendoNativeError -EmitAsError
  } # end PROCESS

<#
.SYNOPSIS

Verbs:
  -dump             -- Dump configuration information or file
  -dumpPFX          -- Dump PFX structure
  -asn              -- Parse ASN.1 file

  -decodehex        -- Decode hexadecimal-encoded file
  -decode           -- Decode Base64-encoded file
  -encode           -- Encode file to Base64

  -deny             -- Deny pending request
  -resubmit         -- Resubmit pending request
  -setattributes    -- Set attributes for pending request
  -setextension     -- Set extension for pending request
  -revoke           -- Revoke Certificate
  -isvalid          -- Display current certificate disposition

  -getconfig        -- Get default configuration string
  -ping             -- Ping Active Directory Certificate Services Request interface
  -pingadmin        -- Ping Active Directory Certificate Services Admin interface
  -CAInfo           -- Display CA Information
  -ca.cert          -- Retrieve the CA's certificate
  -ca.chain         -- Retrieve the CA's certificate chain
  -GetCRL           -- Get CRL
  -CRL              -- Publish new CRLs [or delta CRLs only]
  -shutdown         -- Shutdown Active Directory Certificate Services

  -installCert      -- Install Certification Authority certificate
  -renewCert        -- Renew Certification Authority certificate

  -schema           -- Dump Certificate Schema
  -view             -- Dump Certificate View
  -db               -- Dump Raw Database
  -deleterow        -- Delete server database row

  -backup           -- Backup Active Directory Certificate Services
  -backupDB         -- Backup Active Directory Certificate Services database
  -backupKey        -- Backup Active Directory Certificate Services certificate and private key
  -restore          -- Restore Active Directory Certificate Services
  -restoreDB        -- Restore Active Directory Certificate Services database
  -restoreKey       -- Restore Active Directory Certificate Services certificate and private key
  -importPFX        -- Import certificate and private key
  -dynamicfilelist  -- Display dynamic file List
  -databaselocations -- Display database locations
  -hashfile         -- Generate and display cryptographic hash over a file

  -store            -- Dump certificate store
  -enumstore        -- Enumerate certificate stores
  -addstore         -- Add certificate to store
  -delstore         -- Delete certificate from store
  -verifystore      -- Verify certificate in store
  -repairstore      -- Repair key association or update certificate properties or key security descriptor
  -viewstore        -- Dump certificate store
  -viewdelstore     -- Delete certificate from store
  -UI               -- invoke CryptUI
  -attest           -- Verify Key Attestation Request

  -dsPublish        -- Publish certificate or CRL to Active Directory

  -ADTemplate       -- Display AD templates
  -Template         -- Display Enrollment Policy templates
  -TemplateCAs      -- Display CAs for template
  -CATemplates      -- Display templates for CA
  -SetCASites       -- Manage Site Names for CAs
  -enrollmentServerURL -- Display, add or delete enrollment server URLs associated with a CA
  -ADCA             -- Display AD CAs
  -CA               -- Display Enrollment Policy CAs
  -Policy           -- Display Enrollment Policy
  -PolicyCache      -- Display or delete Enrollment Policy Cache entries
  -CredStore        -- Display, add or delete Credential Store entries
  -InstallDefaultTemplates -- Install default certificate templates
  -URLCache         -- Display or delete URL cache entries
  -pulse            -- Pulse autoenrollment event or NGC task
  -MachineInfo      -- Display Active Directory machine object information
  -DCInfo           -- Display domain controller information
  -EntInfo          -- Display enterprise information
  -TCAInfo          -- Display CA information
  -SCInfo           -- Display smart card information

  -SCRoots          -- Manage smart card root certificates

  -DeleteHelloContainer -- Delete Hello Logon container.  
     ** Users need to sign out after using this option for it to complete. **
  -verifykeys       -- Verify public/private key set
  -verify           -- Verify certificate, CRL or chain
  -verifyCTL        -- Verify AuthRoot or Disallowed Certificates CTL
  -syncWithWU       -- Sync with Windows Update
  -generateSSTFromWU -- Generate SST from Windows Update
  -generatePinRulesCTL -- Generate Pin Rules CTL
  -downloadOcsp     -- Download OCSP Responses and Write to Directory
  -generateHpkpHeader -- Generate HPKP header using certificates in specified file or directory
  -flushCache       -- Flush specified caches in selected process, such as, lsass.exe
  -addEccCurve      -- Add ECC Curve
  -deleteEccCurve   -- Delete ECC Curve
  -displayEccCurve  -- Display ECC Curve
  -sign             -- Re-sign CRL or certificate

  -vroot            -- Create/delete web virtual roots and file shares
  -vocsproot        -- Create/delete web virtual roots for OCSP web proxy
  -addEnrollmentServer -- Add an Enrollment Server application
  -deleteEnrollmentServer -- Delete an Enrollment Server application
  -addPolicyServer  -- Add a Policy Server application
  -deletePolicyServer -- Delete a Policy Server application
  -oid              -- Display ObjectId or set display name
  -error            -- Display error code message text
  -getreg           -- Display registry value
  -setreg           -- Set registry value
  -delreg           -- Delete registry value

  -ImportKMS        -- Import user keys and certificates into server database for key archival
  -ImportCert       -- Import a certificate file into the database
  -GetKey           -- Retrieve archived private key recovery blob, generate a recovery script,
      or recover archived keys
  -RecoverKey       -- Recover archived private key
  -MergePFX         -- Merge PFX files

  -add-chain        -- (-AddChain) Add certificate chain
  -add-pre-chain    -- (-AddPrechain) Add pre-certificate chain
  -get-sth          -- (-GetSTH) Get signed tree head
  -get-sth-consistency -- (-GetSTHConsistency) Get signed tree head changes
  -get-proof-by-hash -- (-GetProofByHash) Get proof by hash
  -get-entries      -- (-GetEntries) Get entries
  -get-roots        -- (-GetRoots) Get roots
  -get-entry-and-proof -- (-GetEntryAndProof) Get entry and proof
  -VerifyCT         -- Verify certificate SCT
  -?                -- Display this usage message


CertUtil -?              -- Display a verb list (command list)
CertUtil -dump -?        -- Display help text for the "dump" verb
CertUtil -v -?           -- Display all help text for all verbs

CertUtil: -? command completed successfully.

.DESCRIPTION See help for C:\Windows\system32\certutil.exe

.PARAMETER CAFullName
Specify the Full Name of the Certificate Authority in the form 'FQDN\CA Name'


.PARAMETER GetReg
Specify Security



#>
}


function Get-PCEnrollmentAgent
{
[PowerShellCustomFunctionAttribute(RequiresElevation=$False)]
[CmdletBinding()]

param(
[Parameter(Mandatory=$true,ParameterSetName='Default')]
[string]$CAFullName,
[Parameter(ParameterSetName='Default')]
[PSDefaultValue(Value="CA\EnrollmentAgentRights")]
[string]$GetReg = "CA\EnrollmentAgentRights"
    )

BEGIN {
    $PSNativeCommandUseErrorActionPreference = $false
    $__CrescendoNativeErrorQueue = [System.Collections.Queue]::new()
    $__PARAMETERMAP = @{
         CAFullName = @{
               OriginalName = '-config'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
         GetReg = @{
               OriginalName = '-getreg'
               OriginalPosition = '1'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
    }

    $__outputHandlers = @{
        Default = @{ StreamOutput = $False; Handler = 'parseEnrollmentAgent' }
    }
}

PROCESS {
    $__boundParameters = $PSBoundParameters
    $__defaultValueParameters = $PSCmdlet.MyInvocation.MyCommand.Parameters.Values.Where({$_.Attributes.Where({$_.TypeId.Name -eq "PSDefaultValueAttribute"})}).Name
    $__defaultValueParameters.Where({ !$__boundParameters["$_"] }).ForEach({$__boundParameters["$_"] = get-variable -value $_})
    $__commandArgs = @()
    $MyInvocation.MyCommand.Parameters.Values.Where({$_.SwitchParameter -and $_.Name -notmatch "Debug|Whatif|Confirm|Verbose" -and ! $__boundParameters[$_.Name]}).ForEach({$__boundParameters[$_.Name] = [switch]::new($false)})
    if ($__boundParameters["Debug"]){wait-debugger}
    $__commandArgs += '-v'
    foreach ($paramName in $__boundParameters.Keys|
            Where-Object {!$__PARAMETERMAP[$_].ApplyToExecutable}|
            Where-Object {!$__PARAMETERMAP[$_].ExcludeAsArgument}|
            Sort-Object {$__PARAMETERMAP[$_].OriginalPosition}) {
        $value = $__boundParameters[$paramName]
        $param = $__PARAMETERMAP[$paramName]
        if ($param) {
            if ($value -is [switch]) {
                 if ($value.IsPresent) {
                     if ($param.OriginalName) { $__commandArgs += $param.OriginalName }
                 }
                 elseif ($param.DefaultMissingValue) { $__commandArgs += $param.DefaultMissingValue }
            }
            elseif ( $param.NoGap ) {
                # if a transform is specified, use it and the construction of the values is up to the transform
                if($param.ArgumentTransform -ne '$args') {
                    $transform = $param.ArgumentTransform
                    if($param.ArgumentTransformType -eq 'inline') {
                        $transform = [scriptblock]::Create($param.ArgumentTransform)
                    }
                    $__commandArgs += & $transform $value
                }
                else {
                    $pFmt = "{0}{1}"
                    # quote the strings if they have spaces
                    if($value -match "\s") { $pFmt = "{0}""{1}""" }
                    $__commandArgs += $pFmt -f $param.OriginalName, $value
                }
            }
            else {
                if($param.OriginalName) { $__commandArgs += $param.OriginalName }
                if($param.ArgumentTransformType -eq 'inline') {
                   $transform = [scriptblock]::Create($param.ArgumentTransform)
                }
                else {
                   $transform = $param.ArgumentTransform
                }
                $__commandArgs += & $transform $value
            }
        }
    }
    $__commandArgs = $__commandArgs | Where-Object {$_ -ne $null}
    if ($__boundParameters["Debug"]){wait-debugger}
    if ( $__boundParameters["Verbose"]) {
         Write-Verbose -Verbose -Message "C:\Windows\system32\certutil.exe"
         $__commandArgs | Write-Verbose -Verbose
    }
    $__handlerInfo = $__outputHandlers[$PSCmdlet.ParameterSetName]
    if (! $__handlerInfo ) {
        $__handlerInfo = $__outputHandlers["Default"] # Guaranteed to be present
    }
    $__handler = $__handlerInfo.Handler
    if ( $PSCmdlet.ShouldProcess("C:\Windows\system32\certutil.exe $__commandArgs")) {
    # check for the application and throw if it cannot be found
        if ( -not (Get-Command -ErrorAction Ignore "C:\Windows\system32\certutil.exe")) {
          throw "Cannot find executable 'C:\Windows\system32\certutil.exe'"
        }
        if ( $__handlerInfo.StreamOutput ) {
            if ( $null -eq $__handler ) {
                & "C:\Windows\system32\certutil.exe" $__commandArgs
            }
            else {
                & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError | & $__handler
            }
        }
        else {
            $result = & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError
            & $__handler $result
        }
    }
    # be sure to let the user know if there are any errors
    Pop-CrescendoNativeError -EmitAsError
  } # end PROCESS

<#
.SYNOPSIS

Verbs:
  -dump             -- Dump configuration information or file
  -dumpPFX          -- Dump PFX structure
  -asn              -- Parse ASN.1 file

  -decodehex        -- Decode hexadecimal-encoded file
  -decode           -- Decode Base64-encoded file
  -encode           -- Encode file to Base64

  -deny             -- Deny pending request
  -resubmit         -- Resubmit pending request
  -setattributes    -- Set attributes for pending request
  -setextension     -- Set extension for pending request
  -revoke           -- Revoke Certificate
  -isvalid          -- Display current certificate disposition

  -getconfig        -- Get default configuration string
  -ping             -- Ping Active Directory Certificate Services Request interface
  -pingadmin        -- Ping Active Directory Certificate Services Admin interface
  -CAInfo           -- Display CA Information
  -ca.cert          -- Retrieve the CA's certificate
  -ca.chain         -- Retrieve the CA's certificate chain
  -GetCRL           -- Get CRL
  -CRL              -- Publish new CRLs [or delta CRLs only]
  -shutdown         -- Shutdown Active Directory Certificate Services

  -installCert      -- Install Certification Authority certificate
  -renewCert        -- Renew Certification Authority certificate

  -schema           -- Dump Certificate Schema
  -view             -- Dump Certificate View
  -db               -- Dump Raw Database
  -deleterow        -- Delete server database row

  -backup           -- Backup Active Directory Certificate Services
  -backupDB         -- Backup Active Directory Certificate Services database
  -backupKey        -- Backup Active Directory Certificate Services certificate and private key
  -restore          -- Restore Active Directory Certificate Services
  -restoreDB        -- Restore Active Directory Certificate Services database
  -restoreKey       -- Restore Active Directory Certificate Services certificate and private key
  -importPFX        -- Import certificate and private key
  -dynamicfilelist  -- Display dynamic file List
  -databaselocations -- Display database locations
  -hashfile         -- Generate and display cryptographic hash over a file

  -store            -- Dump certificate store
  -enumstore        -- Enumerate certificate stores
  -addstore         -- Add certificate to store
  -delstore         -- Delete certificate from store
  -verifystore      -- Verify certificate in store
  -repairstore      -- Repair key association or update certificate properties or key security descriptor
  -viewstore        -- Dump certificate store
  -viewdelstore     -- Delete certificate from store
  -UI               -- invoke CryptUI
  -attest           -- Verify Key Attestation Request

  -dsPublish        -- Publish certificate or CRL to Active Directory

  -ADTemplate       -- Display AD templates
  -Template         -- Display Enrollment Policy templates
  -TemplateCAs      -- Display CAs for template
  -CATemplates      -- Display templates for CA
  -SetCASites       -- Manage Site Names for CAs
  -enrollmentServerURL -- Display, add or delete enrollment server URLs associated with a CA
  -ADCA             -- Display AD CAs
  -CA               -- Display Enrollment Policy CAs
  -Policy           -- Display Enrollment Policy
  -PolicyCache      -- Display or delete Enrollment Policy Cache entries
  -CredStore        -- Display, add or delete Credential Store entries
  -InstallDefaultTemplates -- Install default certificate templates
  -URLCache         -- Display or delete URL cache entries
  -pulse            -- Pulse autoenrollment event or NGC task
  -MachineInfo      -- Display Active Directory machine object information
  -DCInfo           -- Display domain controller information
  -EntInfo          -- Display enterprise information
  -TCAInfo          -- Display CA information
  -SCInfo           -- Display smart card information

  -SCRoots          -- Manage smart card root certificates

  -DeleteHelloContainer -- Delete Hello Logon container.  
     ** Users need to sign out after using this option for it to complete. **
  -verifykeys       -- Verify public/private key set
  -verify           -- Verify certificate, CRL or chain
  -verifyCTL        -- Verify AuthRoot or Disallowed Certificates CTL
  -syncWithWU       -- Sync with Windows Update
  -generateSSTFromWU -- Generate SST from Windows Update
  -generatePinRulesCTL -- Generate Pin Rules CTL
  -downloadOcsp     -- Download OCSP Responses and Write to Directory
  -generateHpkpHeader -- Generate HPKP header using certificates in specified file or directory
  -flushCache       -- Flush specified caches in selected process, such as, lsass.exe
  -addEccCurve      -- Add ECC Curve
  -deleteEccCurve   -- Delete ECC Curve
  -displayEccCurve  -- Display ECC Curve
  -sign             -- Re-sign CRL or certificate

  -vroot            -- Create/delete web virtual roots and file shares
  -vocsproot        -- Create/delete web virtual roots for OCSP web proxy
  -addEnrollmentServer -- Add an Enrollment Server application
  -deleteEnrollmentServer -- Delete an Enrollment Server application
  -addPolicyServer  -- Add a Policy Server application
  -deletePolicyServer -- Delete a Policy Server application
  -oid              -- Display ObjectId or set display name
  -error            -- Display error code message text
  -getreg           -- Display registry value
  -setreg           -- Set registry value
  -delreg           -- Delete registry value

  -ImportKMS        -- Import user keys and certificates into server database for key archival
  -ImportCert       -- Import a certificate file into the database
  -GetKey           -- Retrieve archived private key recovery blob, generate a recovery script,
      or recover archived keys
  -RecoverKey       -- Recover archived private key
  -MergePFX         -- Merge PFX files

  -add-chain        -- (-AddChain) Add certificate chain
  -add-pre-chain    -- (-AddPrechain) Add pre-certificate chain
  -get-sth          -- (-GetSTH) Get signed tree head
  -get-sth-consistency -- (-GetSTHConsistency) Get signed tree head changes
  -get-proof-by-hash -- (-GetProofByHash) Get proof by hash
  -get-entries      -- (-GetEntries) Get entries
  -get-roots        -- (-GetRoots) Get roots
  -get-entry-and-proof -- (-GetEntryAndProof) Get entry and proof
  -VerifyCT         -- Verify certificate SCT
  -?                -- Display this usage message


CertUtil -?              -- Display a verb list (command list)
CertUtil -dump -?        -- Display help text for the "dump" verb
CertUtil -v -?           -- Display all help text for all verbs

CertUtil: -? command completed successfully.

.DESCRIPTION See help for C:\Windows\system32\certutil.exe

.PARAMETER CAFullName
Specify the Full Name of the Certificate Authority in the form 'FQDN\CA Name'


.PARAMETER GetReg
Specify EnrollmentAgentRights



#>
}


function Get-PCOfficerRight
{
[PowerShellCustomFunctionAttribute(RequiresElevation=$False)]
[CmdletBinding()]

param(
[Parameter(Mandatory=$true,ParameterSetName='Default')]
[string]$CAFullName,
[Parameter(ParameterSetName='Default')]
[PSDefaultValue(Value="CA\OfficerRights")]
[string]$GetReg = "CA\OfficerRights"
    )

BEGIN {
    $PSNativeCommandUseErrorActionPreference = $false
    $__CrescendoNativeErrorQueue = [System.Collections.Queue]::new()
    $__PARAMETERMAP = @{
         CAFullName = @{
               OriginalName = '-config'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
         GetReg = @{
               OriginalName = '-getreg'
               OriginalPosition = '1'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
    }

    $__outputHandlers = @{
        Default = @{ StreamOutput = $False; Handler = 'parseOfficerRight' }
    }
}

PROCESS {
    $__boundParameters = $PSBoundParameters
    $__defaultValueParameters = $PSCmdlet.MyInvocation.MyCommand.Parameters.Values.Where({$_.Attributes.Where({$_.TypeId.Name -eq "PSDefaultValueAttribute"})}).Name
    $__defaultValueParameters.Where({ !$__boundParameters["$_"] }).ForEach({$__boundParameters["$_"] = get-variable -value $_})
    $__commandArgs = @()
    $MyInvocation.MyCommand.Parameters.Values.Where({$_.SwitchParameter -and $_.Name -notmatch "Debug|Whatif|Confirm|Verbose" -and ! $__boundParameters[$_.Name]}).ForEach({$__boundParameters[$_.Name] = [switch]::new($false)})
    if ($__boundParameters["Debug"]){wait-debugger}
    $__commandArgs += '-v'
    foreach ($paramName in $__boundParameters.Keys|
            Where-Object {!$__PARAMETERMAP[$_].ApplyToExecutable}|
            Where-Object {!$__PARAMETERMAP[$_].ExcludeAsArgument}|
            Sort-Object {$__PARAMETERMAP[$_].OriginalPosition}) {
        $value = $__boundParameters[$paramName]
        $param = $__PARAMETERMAP[$paramName]
        if ($param) {
            if ($value -is [switch]) {
                 if ($value.IsPresent) {
                     if ($param.OriginalName) { $__commandArgs += $param.OriginalName }
                 }
                 elseif ($param.DefaultMissingValue) { $__commandArgs += $param.DefaultMissingValue }
            }
            elseif ( $param.NoGap ) {
                # if a transform is specified, use it and the construction of the values is up to the transform
                if($param.ArgumentTransform -ne '$args') {
                    $transform = $param.ArgumentTransform
                    if($param.ArgumentTransformType -eq 'inline') {
                        $transform = [scriptblock]::Create($param.ArgumentTransform)
                    }
                    $__commandArgs += & $transform $value
                }
                else {
                    $pFmt = "{0}{1}"
                    # quote the strings if they have spaces
                    if($value -match "\s") { $pFmt = "{0}""{1}""" }
                    $__commandArgs += $pFmt -f $param.OriginalName, $value
                }
            }
            else {
                if($param.OriginalName) { $__commandArgs += $param.OriginalName }
                if($param.ArgumentTransformType -eq 'inline') {
                   $transform = [scriptblock]::Create($param.ArgumentTransform)
                }
                else {
                   $transform = $param.ArgumentTransform
                }
                $__commandArgs += & $transform $value
            }
        }
    }
    $__commandArgs = $__commandArgs | Where-Object {$_ -ne $null}
    if ($__boundParameters["Debug"]){wait-debugger}
    if ( $__boundParameters["Verbose"]) {
         Write-Verbose -Verbose -Message "C:\Windows\system32\certutil.exe"
         $__commandArgs | Write-Verbose -Verbose
    }
    $__handlerInfo = $__outputHandlers[$PSCmdlet.ParameterSetName]
    if (! $__handlerInfo ) {
        $__handlerInfo = $__outputHandlers["Default"] # Guaranteed to be present
    }
    $__handler = $__handlerInfo.Handler
    if ( $PSCmdlet.ShouldProcess("C:\Windows\system32\certutil.exe $__commandArgs")) {
    # check for the application and throw if it cannot be found
        if ( -not (Get-Command -ErrorAction Ignore "C:\Windows\system32\certutil.exe")) {
          throw "Cannot find executable 'C:\Windows\system32\certutil.exe'"
        }
        if ( $__handlerInfo.StreamOutput ) {
            if ( $null -eq $__handler ) {
                & "C:\Windows\system32\certutil.exe" $__commandArgs
            }
            else {
                & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError | & $__handler
            }
        }
        else {
            $result = & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError
            & $__handler $result
        }
    }
    # be sure to let the user know if there are any errors
    Pop-CrescendoNativeError -EmitAsError
  } # end PROCESS

<#
.SYNOPSIS

Verbs:
  -dump             -- Dump configuration information or file
  -dumpPFX          -- Dump PFX structure
  -asn              -- Parse ASN.1 file

  -decodehex        -- Decode hexadecimal-encoded file
  -decode           -- Decode Base64-encoded file
  -encode           -- Encode file to Base64

  -deny             -- Deny pending request
  -resubmit         -- Resubmit pending request
  -setattributes    -- Set attributes for pending request
  -setextension     -- Set extension for pending request
  -revoke           -- Revoke Certificate
  -isvalid          -- Display current certificate disposition

  -getconfig        -- Get default configuration string
  -ping             -- Ping Active Directory Certificate Services Request interface
  -pingadmin        -- Ping Active Directory Certificate Services Admin interface
  -CAInfo           -- Display CA Information
  -ca.cert          -- Retrieve the CA's certificate
  -ca.chain         -- Retrieve the CA's certificate chain
  -GetCRL           -- Get CRL
  -CRL              -- Publish new CRLs [or delta CRLs only]
  -shutdown         -- Shutdown Active Directory Certificate Services

  -installCert      -- Install Certification Authority certificate
  -renewCert        -- Renew Certification Authority certificate

  -schema           -- Dump Certificate Schema
  -view             -- Dump Certificate View
  -db               -- Dump Raw Database
  -deleterow        -- Delete server database row

  -backup           -- Backup Active Directory Certificate Services
  -backupDB         -- Backup Active Directory Certificate Services database
  -backupKey        -- Backup Active Directory Certificate Services certificate and private key
  -restore          -- Restore Active Directory Certificate Services
  -restoreDB        -- Restore Active Directory Certificate Services database
  -restoreKey       -- Restore Active Directory Certificate Services certificate and private key
  -importPFX        -- Import certificate and private key
  -dynamicfilelist  -- Display dynamic file List
  -databaselocations -- Display database locations
  -hashfile         -- Generate and display cryptographic hash over a file

  -store            -- Dump certificate store
  -enumstore        -- Enumerate certificate stores
  -addstore         -- Add certificate to store
  -delstore         -- Delete certificate from store
  -verifystore      -- Verify certificate in store
  -repairstore      -- Repair key association or update certificate properties or key security descriptor
  -viewstore        -- Dump certificate store
  -viewdelstore     -- Delete certificate from store
  -UI               -- invoke CryptUI
  -attest           -- Verify Key Attestation Request

  -dsPublish        -- Publish certificate or CRL to Active Directory

  -ADTemplate       -- Display AD templates
  -Template         -- Display Enrollment Policy templates
  -TemplateCAs      -- Display CAs for template
  -CATemplates      -- Display templates for CA
  -SetCASites       -- Manage Site Names for CAs
  -enrollmentServerURL -- Display, add or delete enrollment server URLs associated with a CA
  -ADCA             -- Display AD CAs
  -CA               -- Display Enrollment Policy CAs
  -Policy           -- Display Enrollment Policy
  -PolicyCache      -- Display or delete Enrollment Policy Cache entries
  -CredStore        -- Display, add or delete Credential Store entries
  -InstallDefaultTemplates -- Install default certificate templates
  -URLCache         -- Display or delete URL cache entries
  -pulse            -- Pulse autoenrollment event or NGC task
  -MachineInfo      -- Display Active Directory machine object information
  -DCInfo           -- Display domain controller information
  -EntInfo          -- Display enterprise information
  -TCAInfo          -- Display CA information
  -SCInfo           -- Display smart card information

  -SCRoots          -- Manage smart card root certificates

  -DeleteHelloContainer -- Delete Hello Logon container.  
     ** Users need to sign out after using this option for it to complete. **
  -verifykeys       -- Verify public/private key set
  -verify           -- Verify certificate, CRL or chain
  -verifyCTL        -- Verify AuthRoot or Disallowed Certificates CTL
  -syncWithWU       -- Sync with Windows Update
  -generateSSTFromWU -- Generate SST from Windows Update
  -generatePinRulesCTL -- Generate Pin Rules CTL
  -downloadOcsp     -- Download OCSP Responses and Write to Directory
  -generateHpkpHeader -- Generate HPKP header using certificates in specified file or directory
  -flushCache       -- Flush specified caches in selected process, such as, lsass.exe
  -addEccCurve      -- Add ECC Curve
  -deleteEccCurve   -- Delete ECC Curve
  -displayEccCurve  -- Display ECC Curve
  -sign             -- Re-sign CRL or certificate

  -vroot            -- Create/delete web virtual roots and file shares
  -vocsproot        -- Create/delete web virtual roots for OCSP web proxy
  -addEnrollmentServer -- Add an Enrollment Server application
  -deleteEnrollmentServer -- Delete an Enrollment Server application
  -addPolicyServer  -- Add a Policy Server application
  -deletePolicyServer -- Delete a Policy Server application
  -oid              -- Display ObjectId or set display name
  -error            -- Display error code message text
  -getreg           -- Display registry value
  -setreg           -- Set registry value
  -delreg           -- Delete registry value

  -ImportKMS        -- Import user keys and certificates into server database for key archival
  -ImportCert       -- Import a certificate file into the database
  -GetKey           -- Retrieve archived private key recovery blob, generate a recovery script,
      or recover archived keys
  -RecoverKey       -- Recover archived private key
  -MergePFX         -- Merge PFX files

  -add-chain        -- (-AddChain) Add certificate chain
  -add-pre-chain    -- (-AddPrechain) Add pre-certificate chain
  -get-sth          -- (-GetSTH) Get signed tree head
  -get-sth-consistency -- (-GetSTHConsistency) Get signed tree head changes
  -get-proof-by-hash -- (-GetProofByHash) Get proof by hash
  -get-entries      -- (-GetEntries) Get entries
  -get-roots        -- (-GetRoots) Get roots
  -get-entry-and-proof -- (-GetEntryAndProof) Get entry and proof
  -VerifyCT         -- Verify certificate SCT
  -?                -- Display this usage message


CertUtil -?              -- Display a verb list (command list)
CertUtil -dump -?        -- Display help text for the "dump" verb
CertUtil -v -?           -- Display all help text for all verbs

CertUtil: -? command completed successfully.

.DESCRIPTION See help for C:\Windows\system32\certutil.exe

.PARAMETER CAFullName
Specify the Full Name of the Certificate Authority in the form 'FQDN\CA Name'


.PARAMETER GetReg
Specify OfficerRights



#>
}


function Get-PCEditFlag
{
[PowerShellCustomFunctionAttribute(RequiresElevation=$False)]
[CmdletBinding()]

param(
[Parameter(Mandatory=$true,ParameterSetName='Default')]
[string]$CAFullName,
[Parameter(ParameterSetName='Default')]
[PSDefaultValue(Value="policy\EditFlags")]
[string]$GetReg = "policy\EditFlags"
    )

BEGIN {
    $PSNativeCommandUseErrorActionPreference = $false
    $__CrescendoNativeErrorQueue = [System.Collections.Queue]::new()
    $__PARAMETERMAP = @{
         CAFullName = @{
               OriginalName = '-config'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
         GetReg = @{
               OriginalName = '-getreg'
               OriginalPosition = '1'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
    }

    $__outputHandlers = @{
        Default = @{ StreamOutput = $False; Handler = 'parseEditFlag' }
    }
}

PROCESS {
    $__boundParameters = $PSBoundParameters
    $__defaultValueParameters = $PSCmdlet.MyInvocation.MyCommand.Parameters.Values.Where({$_.Attributes.Where({$_.TypeId.Name -eq "PSDefaultValueAttribute"})}).Name
    $__defaultValueParameters.Where({ !$__boundParameters["$_"] }).ForEach({$__boundParameters["$_"] = get-variable -value $_})
    $__commandArgs = @()
    $MyInvocation.MyCommand.Parameters.Values.Where({$_.SwitchParameter -and $_.Name -notmatch "Debug|Whatif|Confirm|Verbose" -and ! $__boundParameters[$_.Name]}).ForEach({$__boundParameters[$_.Name] = [switch]::new($false)})
    if ($__boundParameters["Debug"]){wait-debugger}
    $__commandArgs += '-v'
    foreach ($paramName in $__boundParameters.Keys|
            Where-Object {!$__PARAMETERMAP[$_].ApplyToExecutable}|
            Where-Object {!$__PARAMETERMAP[$_].ExcludeAsArgument}|
            Sort-Object {$__PARAMETERMAP[$_].OriginalPosition}) {
        $value = $__boundParameters[$paramName]
        $param = $__PARAMETERMAP[$paramName]
        if ($param) {
            if ($value -is [switch]) {
                 if ($value.IsPresent) {
                     if ($param.OriginalName) { $__commandArgs += $param.OriginalName }
                 }
                 elseif ($param.DefaultMissingValue) { $__commandArgs += $param.DefaultMissingValue }
            }
            elseif ( $param.NoGap ) {
                # if a transform is specified, use it and the construction of the values is up to the transform
                if($param.ArgumentTransform -ne '$args') {
                    $transform = $param.ArgumentTransform
                    if($param.ArgumentTransformType -eq 'inline') {
                        $transform = [scriptblock]::Create($param.ArgumentTransform)
                    }
                    $__commandArgs += & $transform $value
                }
                else {
                    $pFmt = "{0}{1}"
                    # quote the strings if they have spaces
                    if($value -match "\s") { $pFmt = "{0}""{1}""" }
                    $__commandArgs += $pFmt -f $param.OriginalName, $value
                }
            }
            else {
                if($param.OriginalName) { $__commandArgs += $param.OriginalName }
                if($param.ArgumentTransformType -eq 'inline') {
                   $transform = [scriptblock]::Create($param.ArgumentTransform)
                }
                else {
                   $transform = $param.ArgumentTransform
                }
                $__commandArgs += & $transform $value
            }
        }
    }
    $__commandArgs = $__commandArgs | Where-Object {$_ -ne $null}
    if ($__boundParameters["Debug"]){wait-debugger}
    if ( $__boundParameters["Verbose"]) {
         Write-Verbose -Verbose -Message "C:/Windows/system32/certutil.exe"
         $__commandArgs | Write-Verbose -Verbose
    }
    $__handlerInfo = $__outputHandlers[$PSCmdlet.ParameterSetName]
    if (! $__handlerInfo ) {
        $__handlerInfo = $__outputHandlers["Default"] # Guaranteed to be present
    }
    $__handler = $__handlerInfo.Handler
    if ( $PSCmdlet.ShouldProcess("C:/Windows/system32/certutil.exe $__commandArgs")) {
    # check for the application and throw if it cannot be found
        if ( -not (Get-Command -ErrorAction Ignore "C:/Windows/system32/certutil.exe")) {
          throw "Cannot find executable 'C:/Windows/system32/certutil.exe'"
        }
        if ( $__handlerInfo.StreamOutput ) {
            if ( $null -eq $__handler ) {
                & "C:/Windows/system32/certutil.exe" $__commandArgs
            }
            else {
                & "C:/Windows/system32/certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError | & $__handler
            }
        }
        else {
            $result = & "C:/Windows/system32/certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError
            & $__handler $result
        }
    }
    # be sure to let the user know if there are any errors
    Pop-CrescendoNativeError -EmitAsError
  } # end PROCESS

<#
.SYNOPSIS

Verbs:
  -dump             -- Dump configuration information or file
  -dumpPFX          -- Dump PFX structure
  -asn              -- Parse ASN.1 file

  -decodehex        -- Decode hexadecimal-encoded file
  -decode           -- Decode Base64-encoded file
  -encode           -- Encode file to Base64

  -deny             -- Deny pending request
  -resubmit         -- Resubmit pending request
  -setattributes    -- Set attributes for pending request
  -setextension     -- Set extension for pending request
  -revoke           -- Revoke Certificate
  -isvalid          -- Display current certificate disposition

  -getconfig        -- Get default configuration string
  -ping             -- Ping Active Directory Certificate Services Request interface
  -pingadmin        -- Ping Active Directory Certificate Services Admin interface
  -CAInfo           -- Display CA Information
  -ca.cert          -- Retrieve the CA's certificate
  -ca.chain         -- Retrieve the CA's certificate chain
  -GetCRL           -- Get CRL
  -CRL              -- Publish new CRLs [or delta CRLs only]
  -shutdown         -- Shutdown Active Directory Certificate Services

  -installCert      -- Install Certification Authority certificate
  -renewCert        -- Renew Certification Authority certificate

  -schema           -- Dump Certificate Schema
  -view             -- Dump Certificate View
  -db               -- Dump Raw Database
  -deleterow        -- Delete server database row

  -backup           -- Backup Active Directory Certificate Services
  -backupDB         -- Backup Active Directory Certificate Services database
  -backupKey        -- Backup Active Directory Certificate Services certificate and private key
  -restore          -- Restore Active Directory Certificate Services
  -restoreDB        -- Restore Active Directory Certificate Services database
  -restoreKey       -- Restore Active Directory Certificate Services certificate and private key
  -importPFX        -- Import certificate and private key
  -dynamicfilelist  -- Display dynamic file List
  -databaselocations -- Display database locations
  -hashfile         -- Generate and display cryptographic hash over a file

  -store            -- Dump certificate store
  -enumstore        -- Enumerate certificate stores
  -addstore         -- Add certificate to store
  -delstore         -- Delete certificate from store
  -verifystore      -- Verify certificate in store
  -repairstore      -- Repair key association or update certificate properties or key security descriptor
  -viewstore        -- Dump certificate store
  -viewdelstore     -- Delete certificate from store
  -UI               -- invoke CryptUI
  -attest           -- Verify Key Attestation Request

  -dsPublish        -- Publish certificate or CRL to Active Directory

  -ADTemplate       -- Display AD templates
  -Template         -- Display Enrollment Policy templates
  -TemplateCAs      -- Display CAs for template
  -CATemplates      -- Display templates for CA
  -SetCASites       -- Manage Site Names for CAs
  -enrollmentServerURL -- Display, add or delete enrollment server URLs associated with a CA
  -ADCA             -- Display AD CAs
  -CA               -- Display Enrollment Policy CAs
  -Policy           -- Display Enrollment Policy
  -PolicyCache      -- Display or delete Enrollment Policy Cache entries
  -CredStore        -- Display, add or delete Credential Store entries
  -InstallDefaultTemplates -- Install default certificate templates
  -URLCache         -- Display or delete URL cache entries
  -pulse            -- Pulse autoenrollment event or NGC task
  -MachineInfo      -- Display Active Directory machine object information
  -DCInfo           -- Display domain controller information
  -EntInfo          -- Display enterprise information
  -TCAInfo          -- Display CA information
  -SCInfo           -- Display smart card information

  -SCRoots          -- Manage smart card root certificates

  -DeleteHelloContainer -- Delete Hello Logon container.  
     ** Users need to sign out after using this option for it to complete. **
  -verifykeys       -- Verify public/private key set
  -verify           -- Verify certificate, CRL or chain
  -verifyCTL        -- Verify AuthRoot or Disallowed Certificates CTL
  -syncWithWU       -- Sync with Windows Update
  -generateSSTFromWU -- Generate SST from Windows Update
  -generatePinRulesCTL -- Generate Pin Rules CTL
  -downloadOcsp     -- Download OCSP Responses and Write to Directory
  -generateHpkpHeader -- Generate HPKP header using certificates in specified file or directory
  -flushCache       -- Flush specified caches in selected process, such as, lsass.exe
  -addEccCurve      -- Add ECC Curve
  -deleteEccCurve   -- Delete ECC Curve
  -displayEccCurve  -- Display ECC Curve
  -sign             -- Re-sign CRL or certificate

  -vroot            -- Create/delete web virtual roots and file shares
  -vocsproot        -- Create/delete web virtual roots for OCSP web proxy
  -addEnrollmentServer -- Add an Enrollment Server application
  -deleteEnrollmentServer -- Delete an Enrollment Server application
  -addPolicyServer  -- Add a Policy Server application
  -deletePolicyServer -- Delete a Policy Server application
  -oid              -- Display ObjectId or set display name
  -error            -- Display error code message text
  -getreg           -- Display registry value
  -setreg           -- Set registry value
  -delreg           -- Delete registry value

  -ImportKMS        -- Import user keys and certificates into server database for key archival
  -ImportCert       -- Import a certificate file into the database
  -GetKey           -- Retrieve archived private key recovery blob, generate a recovery script,
      or recover archived keys
  -RecoverKey       -- Recover archived private key
  -MergePFX         -- Merge PFX files

  -add-chain        -- (-AddChain) Add certificate chain
  -add-pre-chain    -- (-AddPrechain) Add pre-certificate chain
  -get-sth          -- (-GetSTH) Get signed tree head
  -get-sth-consistency -- (-GetSTHConsistency) Get signed tree head changes
  -get-proof-by-hash -- (-GetProofByHash) Get proof by hash
  -get-entries      -- (-GetEntries) Get entries
  -get-roots        -- (-GetRoots) Get roots
  -get-entry-and-proof -- (-GetEntryAndProof) Get entry and proof
  -VerifyCT         -- Verify certificate SCT
  -?                -- Display this usage message


CertUtil -?              -- Display a verb list (command list)
CertUtil -dump -?        -- Display help text for the "dump" verb
CertUtil -v -?           -- Display all help text for all verbs

CertUtil: -? command completed successfully.

.DESCRIPTION See help for C:/Windows/system32/certutil.exe

.PARAMETER CAFullName
Specify the Full Name of the Certificate Authority in the form 'FQDN\CA Name'


.PARAMETER GetReg
Specify EditFlags



#>
}


function Get-PCInterfaceFlag
{
[PowerShellCustomFunctionAttribute(RequiresElevation=$False)]
[CmdletBinding()]

param(
[Parameter(Mandatory=$true,ParameterSetName='Default')]
[string]$CAFullName,
[Parameter(ParameterSetName='Default')]
[PSDefaultValue(Value="CA\InterfaceFlags")]
[string]$GetReg = "CA\InterfaceFlags"
    )

BEGIN {
    $PSNativeCommandUseErrorActionPreference = $false
    $__CrescendoNativeErrorQueue = [System.Collections.Queue]::new()
    $__PARAMETERMAP = @{
         CAFullName = @{
               OriginalName = '-config'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
         GetReg = @{
               OriginalName = '-getreg'
               OriginalPosition = '1'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
    }

    $__outputHandlers = @{
        Default = @{ StreamOutput = $False; Handler = 'parseInterfaceFlag' }
    }
}

PROCESS {
    $__boundParameters = $PSBoundParameters
    $__defaultValueParameters = $PSCmdlet.MyInvocation.MyCommand.Parameters.Values.Where({$_.Attributes.Where({$_.TypeId.Name -eq "PSDefaultValueAttribute"})}).Name
    $__defaultValueParameters.Where({ !$__boundParameters["$_"] }).ForEach({$__boundParameters["$_"] = get-variable -value $_})
    $__commandArgs = @()
    $MyInvocation.MyCommand.Parameters.Values.Where({$_.SwitchParameter -and $_.Name -notmatch "Debug|Whatif|Confirm|Verbose" -and ! $__boundParameters[$_.Name]}).ForEach({$__boundParameters[$_.Name] = [switch]::new($false)})
    if ($__boundParameters["Debug"]){wait-debugger}
    $__commandArgs += '-v'
    foreach ($paramName in $__boundParameters.Keys|
            Where-Object {!$__PARAMETERMAP[$_].ApplyToExecutable}|
            Where-Object {!$__PARAMETERMAP[$_].ExcludeAsArgument}|
            Sort-Object {$__PARAMETERMAP[$_].OriginalPosition}) {
        $value = $__boundParameters[$paramName]
        $param = $__PARAMETERMAP[$paramName]
        if ($param) {
            if ($value -is [switch]) {
                 if ($value.IsPresent) {
                     if ($param.OriginalName) { $__commandArgs += $param.OriginalName }
                 }
                 elseif ($param.DefaultMissingValue) { $__commandArgs += $param.DefaultMissingValue }
            }
            elseif ( $param.NoGap ) {
                # if a transform is specified, use it and the construction of the values is up to the transform
                if($param.ArgumentTransform -ne '$args') {
                    $transform = $param.ArgumentTransform
                    if($param.ArgumentTransformType -eq 'inline') {
                        $transform = [scriptblock]::Create($param.ArgumentTransform)
                    }
                    $__commandArgs += & $transform $value
                }
                else {
                    $pFmt = "{0}{1}"
                    # quote the strings if they have spaces
                    if($value -match "\s") { $pFmt = "{0}""{1}""" }
                    $__commandArgs += $pFmt -f $param.OriginalName, $value
                }
            }
            else {
                if($param.OriginalName) { $__commandArgs += $param.OriginalName }
                if($param.ArgumentTransformType -eq 'inline') {
                   $transform = [scriptblock]::Create($param.ArgumentTransform)
                }
                else {
                   $transform = $param.ArgumentTransform
                }
                $__commandArgs += & $transform $value
            }
        }
    }
    $__commandArgs = $__commandArgs | Where-Object {$_ -ne $null}
    if ($__boundParameters["Debug"]){wait-debugger}
    if ( $__boundParameters["Verbose"]) {
         Write-Verbose -Verbose -Message "C:/Windows/system32/certutil.exe"
         $__commandArgs | Write-Verbose -Verbose
    }
    $__handlerInfo = $__outputHandlers[$PSCmdlet.ParameterSetName]
    if (! $__handlerInfo ) {
        $__handlerInfo = $__outputHandlers["Default"] # Guaranteed to be present
    }
    $__handler = $__handlerInfo.Handler
    if ( $PSCmdlet.ShouldProcess("C:/Windows/system32/certutil.exe $__commandArgs")) {
    # check for the application and throw if it cannot be found
        if ( -not (Get-Command -ErrorAction Ignore "C:/Windows/system32/certutil.exe")) {
          throw "Cannot find executable 'C:/Windows/system32/certutil.exe'"
        }
        if ( $__handlerInfo.StreamOutput ) {
            if ( $null -eq $__handler ) {
                & "C:/Windows/system32/certutil.exe" $__commandArgs
            }
            else {
                & "C:/Windows/system32/certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError | & $__handler
            }
        }
        else {
            $result = & "C:/Windows/system32/certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError
            & $__handler $result
        }
    }
    # be sure to let the user know if there are any errors
    Pop-CrescendoNativeError -EmitAsError
  } # end PROCESS

<#
.SYNOPSIS

Verbs:
  -dump             -- Dump configuration information or file
  -dumpPFX          -- Dump PFX structure
  -asn              -- Parse ASN.1 file

  -decodehex        -- Decode hexadecimal-encoded file
  -decode           -- Decode Base64-encoded file
  -encode           -- Encode file to Base64

  -deny             -- Deny pending request
  -resubmit         -- Resubmit pending request
  -setattributes    -- Set attributes for pending request
  -setextension     -- Set extension for pending request
  -revoke           -- Revoke Certificate
  -isvalid          -- Display current certificate disposition

  -getconfig        -- Get default configuration string
  -ping             -- Ping Active Directory Certificate Services Request interface
  -pingadmin        -- Ping Active Directory Certificate Services Admin interface
  -CAInfo           -- Display CA Information
  -ca.cert          -- Retrieve the CA's certificate
  -ca.chain         -- Retrieve the CA's certificate chain
  -GetCRL           -- Get CRL
  -CRL              -- Publish new CRLs [or delta CRLs only]
  -shutdown         -- Shutdown Active Directory Certificate Services

  -installCert      -- Install Certification Authority certificate
  -renewCert        -- Renew Certification Authority certificate

  -schema           -- Dump Certificate Schema
  -view             -- Dump Certificate View
  -db               -- Dump Raw Database
  -deleterow        -- Delete server database row

  -backup           -- Backup Active Directory Certificate Services
  -backupDB         -- Backup Active Directory Certificate Services database
  -backupKey        -- Backup Active Directory Certificate Services certificate and private key
  -restore          -- Restore Active Directory Certificate Services
  -restoreDB        -- Restore Active Directory Certificate Services database
  -restoreKey       -- Restore Active Directory Certificate Services certificate and private key
  -importPFX        -- Import certificate and private key
  -dynamicfilelist  -- Display dynamic file List
  -databaselocations -- Display database locations
  -hashfile         -- Generate and display cryptographic hash over a file

  -store            -- Dump certificate store
  -enumstore        -- Enumerate certificate stores
  -addstore         -- Add certificate to store
  -delstore         -- Delete certificate from store
  -verifystore      -- Verify certificate in store
  -repairstore      -- Repair key association or update certificate properties or key security descriptor
  -viewstore        -- Dump certificate store
  -viewdelstore     -- Delete certificate from store
  -UI               -- invoke CryptUI
  -attest           -- Verify Key Attestation Request

  -dsPublish        -- Publish certificate or CRL to Active Directory

  -ADTemplate       -- Display AD templates
  -Template         -- Display Enrollment Policy templates
  -TemplateCAs      -- Display CAs for template
  -CATemplates      -- Display templates for CA
  -SetCASites       -- Manage Site Names for CAs
  -enrollmentServerURL -- Display, add or delete enrollment server URLs associated with a CA
  -ADCA             -- Display AD CAs
  -CA               -- Display Enrollment Policy CAs
  -Policy           -- Display Enrollment Policy
  -PolicyCache      -- Display or delete Enrollment Policy Cache entries
  -CredStore        -- Display, add or delete Credential Store entries
  -InstallDefaultTemplates -- Install default certificate templates
  -URLCache         -- Display or delete URL cache entries
  -pulse            -- Pulse autoenrollment event or NGC task
  -MachineInfo      -- Display Active Directory machine object information
  -DCInfo           -- Display domain controller information
  -EntInfo          -- Display enterprise information
  -TCAInfo          -- Display CA information
  -SCInfo           -- Display smart card information

  -SCRoots          -- Manage smart card root certificates

  -DeleteHelloContainer -- Delete Hello Logon container.  
     ** Users need to sign out after using this option for it to complete. **
  -verifykeys       -- Verify public/private key set
  -verify           -- Verify certificate, CRL or chain
  -verifyCTL        -- Verify AuthRoot or Disallowed Certificates CTL
  -syncWithWU       -- Sync with Windows Update
  -generateSSTFromWU -- Generate SST from Windows Update
  -generatePinRulesCTL -- Generate Pin Rules CTL
  -downloadOcsp     -- Download OCSP Responses and Write to Directory
  -generateHpkpHeader -- Generate HPKP header using certificates in specified file or directory
  -flushCache       -- Flush specified caches in selected process, such as, lsass.exe
  -addEccCurve      -- Add ECC Curve
  -deleteEccCurve   -- Delete ECC Curve
  -displayEccCurve  -- Display ECC Curve
  -sign             -- Re-sign CRL or certificate

  -vroot            -- Create/delete web virtual roots and file shares
  -vocsproot        -- Create/delete web virtual roots for OCSP web proxy
  -addEnrollmentServer -- Add an Enrollment Server application
  -deleteEnrollmentServer -- Delete an Enrollment Server application
  -addPolicyServer  -- Add a Policy Server application
  -deletePolicyServer -- Delete a Policy Server application
  -oid              -- Display ObjectId or set display name
  -error            -- Display error code message text
  -getreg           -- Display registry value
  -setreg           -- Set registry value
  -delreg           -- Delete registry value

  -ImportKMS        -- Import user keys and certificates into server database for key archival
  -ImportCert       -- Import a certificate file into the database
  -GetKey           -- Retrieve archived private key recovery blob, generate a recovery script,
      or recover archived keys
  -RecoverKey       -- Recover archived private key
  -MergePFX         -- Merge PFX files

  -add-chain        -- (-AddChain) Add certificate chain
  -add-pre-chain    -- (-AddPrechain) Add pre-certificate chain
  -get-sth          -- (-GetSTH) Get signed tree head
  -get-sth-consistency -- (-GetSTHConsistency) Get signed tree head changes
  -get-proof-by-hash -- (-GetProofByHash) Get proof by hash
  -get-entries      -- (-GetEntries) Get entries
  -get-roots        -- (-GetRoots) Get roots
  -get-entry-and-proof -- (-GetEntryAndProof) Get entry and proof
  -VerifyCT         -- Verify certificate SCT
  -?                -- Display this usage message


CertUtil -?              -- Display a verb list (command list)
CertUtil -dump -?        -- Display help text for the "dump" verb
CertUtil -v -?           -- Display all help text for all verbs

CertUtil: -? command completed successfully.

.DESCRIPTION See help for C:/Windows/system32/certutil.exe

.PARAMETER CAFullName
Specify the Full Name of the Certificate Authority in the form 'FQDN\CA Name'


.PARAMETER GetReg
Specify InterfaceFlags



#>
}


function Get-PCAuditFilter
{
[PowerShellCustomFunctionAttribute(RequiresElevation=$False)]
[CmdletBinding()]

param(
[Parameter(Mandatory=$true,ParameterSetName='Default')]
[string]$CAFullName,
[Parameter(ParameterSetName='Default')]
[PSDefaultValue(Value="CA\AuditFilter")]
[string]$GetReg = "CA\AuditFilter"
    )

BEGIN {
    $PSNativeCommandUseErrorActionPreference = $false
    $__CrescendoNativeErrorQueue = [System.Collections.Queue]::new()
    $__PARAMETERMAP = @{
         CAFullName = @{
               OriginalName = '-config'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
         GetReg = @{
               OriginalName = '-getreg'
               OriginalPosition = '1'
               Position = '2147483647'
               ParameterType = 'string'
               ApplyToExecutable = $False
               NoGap = $False
               ArgumentTransform = '$args'
               ArgumentTransformType = 'inline'
               }
    }

    $__outputHandlers = @{
        Default = @{ StreamOutput = $False; Handler = 'parseAuditFilter' }
    }
}

PROCESS {
    $__boundParameters = $PSBoundParameters
    $__defaultValueParameters = $PSCmdlet.MyInvocation.MyCommand.Parameters.Values.Where({$_.Attributes.Where({$_.TypeId.Name -eq "PSDefaultValueAttribute"})}).Name
    $__defaultValueParameters.Where({ !$__boundParameters["$_"] }).ForEach({$__boundParameters["$_"] = get-variable -value $_})
    $__commandArgs = @()
    $MyInvocation.MyCommand.Parameters.Values.Where({$_.SwitchParameter -and $_.Name -notmatch "Debug|Whatif|Confirm|Verbose" -and ! $__boundParameters[$_.Name]}).ForEach({$__boundParameters[$_.Name] = [switch]::new($false)})
    if ($__boundParameters["Debug"]){wait-debugger}
    foreach ($paramName in $__boundParameters.Keys|
            Where-Object {!$__PARAMETERMAP[$_].ApplyToExecutable}|
            Where-Object {!$__PARAMETERMAP[$_].ExcludeAsArgument}|
            Sort-Object {$__PARAMETERMAP[$_].OriginalPosition}) {
        $value = $__boundParameters[$paramName]
        $param = $__PARAMETERMAP[$paramName]
        if ($param) {
            if ($value -is [switch]) {
                 if ($value.IsPresent) {
                     if ($param.OriginalName) { $__commandArgs += $param.OriginalName }
                 }
                 elseif ($param.DefaultMissingValue) { $__commandArgs += $param.DefaultMissingValue }
            }
            elseif ( $param.NoGap ) {
                # if a transform is specified, use it and the construction of the values is up to the transform
                if($param.ArgumentTransform -ne '$args') {
                    $transform = $param.ArgumentTransform
                    if($param.ArgumentTransformType -eq 'inline') {
                        $transform = [scriptblock]::Create($param.ArgumentTransform)
                    }
                    $__commandArgs += & $transform $value
                }
                else {
                    $pFmt = "{0}{1}"
                    # quote the strings if they have spaces
                    if($value -match "\s") { $pFmt = "{0}""{1}""" }
                    $__commandArgs += $pFmt -f $param.OriginalName, $value
                }
            }
            else {
                if($param.OriginalName) { $__commandArgs += $param.OriginalName }
                if($param.ArgumentTransformType -eq 'inline') {
                   $transform = [scriptblock]::Create($param.ArgumentTransform)
                }
                else {
                   $transform = $param.ArgumentTransform
                }
                $__commandArgs += & $transform $value
            }
        }
    }
    $__commandArgs = $__commandArgs | Where-Object {$_ -ne $null}
    if ($__boundParameters["Debug"]){wait-debugger}
    if ( $__boundParameters["Verbose"]) {
         Write-Verbose -Verbose -Message "C:\Windows\system32\certutil.exe"
         $__commandArgs | Write-Verbose -Verbose
    }
    $__handlerInfo = $__outputHandlers[$PSCmdlet.ParameterSetName]
    if (! $__handlerInfo ) {
        $__handlerInfo = $__outputHandlers["Default"] # Guaranteed to be present
    }
    $__handler = $__handlerInfo.Handler
    if ( $PSCmdlet.ShouldProcess("C:\Windows\system32\certutil.exe $__commandArgs")) {
    # check for the application and throw if it cannot be found
        if ( -not (Get-Command -ErrorAction Ignore "C:\Windows\system32\certutil.exe")) {
          throw "Cannot find executable 'C:\Windows\system32\certutil.exe'"
        }
        if ( $__handlerInfo.StreamOutput ) {
            if ( $null -eq $__handler ) {
                & "C:\Windows\system32\certutil.exe" $__commandArgs
            }
            else {
                & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError | & $__handler
            }
        }
        else {
            $result = & "C:\Windows\system32\certutil.exe" $__commandArgs 2>&1| Push-CrescendoNativeError
            & $__handler $result
        }
    }
    # be sure to let the user know if there are any errors
    Pop-CrescendoNativeError -EmitAsError
  } # end PROCESS

<#
.SYNOPSIS

Verbs:
  -dump             -- Dump configuration information or file
  -dumpPFX          -- Dump PFX structure
  -asn              -- Parse ASN.1 file

  -decodehex        -- Decode hexadecimal-encoded file
  -decode           -- Decode Base64-encoded file
  -encode           -- Encode file to Base64

  -deny             -- Deny pending request
  -resubmit         -- Resubmit pending request
  -setattributes    -- Set attributes for pending request
  -setextension     -- Set extension for pending request
  -revoke           -- Revoke Certificate
  -isvalid          -- Display current certificate disposition

  -getconfig        -- Get default configuration string
  -ping             -- Ping Active Directory Certificate Services Request interface
  -pingadmin        -- Ping Active Directory Certificate Services Admin interface
  -CAInfo           -- Display CA Information
  -ca.cert          -- Retrieve the CA's certificate
  -ca.chain         -- Retrieve the CA's certificate chain
  -GetCRL           -- Get CRL
  -CRL              -- Publish new CRLs [or delta CRLs only]
  -shutdown         -- Shutdown Active Directory Certificate Services

  -installCert      -- Install Certification Authority certificate
  -renewCert        -- Renew Certification Authority certificate

  -schema           -- Dump Certificate Schema
  -view             -- Dump Certificate View
  -db               -- Dump Raw Database
  -deleterow        -- Delete server database row

  -backup           -- Backup Active Directory Certificate Services
  -backupDB         -- Backup Active Directory Certificate Services database
  -backupKey        -- Backup Active Directory Certificate Services certificate and private key
  -restore          -- Restore Active Directory Certificate Services
  -restoreDB        -- Restore Active Directory Certificate Services database
  -restoreKey       -- Restore Active Directory Certificate Services certificate and private key
  -importPFX        -- Import certificate and private key
  -dynamicfilelist  -- Display dynamic file List
  -databaselocations -- Display database locations
  -hashfile         -- Generate and display cryptographic hash over a file

  -store            -- Dump certificate store
  -enumstore        -- Enumerate certificate stores
  -addstore         -- Add certificate to store
  -delstore         -- Delete certificate from store
  -verifystore      -- Verify certificate in store
  -repairstore      -- Repair key association or update certificate properties or key security descriptor
  -viewstore        -- Dump certificate store
  -viewdelstore     -- Delete certificate from store
  -UI               -- invoke CryptUI
  -attest           -- Verify Key Attestation Request

  -dsPublish        -- Publish certificate or CRL to Active Directory

  -ADTemplate       -- Display AD templates
  -Template         -- Display Enrollment Policy templates
  -TemplateCAs      -- Display CAs for template
  -CATemplates      -- Display templates for CA
  -SetCASites       -- Manage Site Names for CAs
  -enrollmentServerURL -- Display, add or delete enrollment server URLs associated with a CA
  -ADCA             -- Display AD CAs
  -CA               -- Display Enrollment Policy CAs
  -Policy           -- Display Enrollment Policy
  -PolicyCache      -- Display or delete Enrollment Policy Cache entries
  -CredStore        -- Display, add or delete Credential Store entries
  -InstallDefaultTemplates -- Install default certificate templates
  -URLCache         -- Display or delete URL cache entries
  -pulse            -- Pulse autoenrollment event or NGC task
  -MachineInfo      -- Display Active Directory machine object information
  -DCInfo           -- Display domain controller information
  -EntInfo          -- Display enterprise information
  -TCAInfo          -- Display CA information
  -SCInfo           -- Display smart card information

  -SCRoots          -- Manage smart card root certificates

  -DeleteHelloContainer -- Delete Hello Logon container.  
     ** Users need to sign out after using this option for it to complete. **
  -verifykeys       -- Verify public/private key set
  -verify           -- Verify certificate, CRL or chain
  -verifyCTL        -- Verify AuthRoot or Disallowed Certificates CTL
  -syncWithWU       -- Sync with Windows Update
  -generateSSTFromWU -- Generate SST from Windows Update
  -generatePinRulesCTL -- Generate Pin Rules CTL
  -downloadOcsp     -- Download OCSP Responses and Write to Directory
  -generateHpkpHeader -- Generate HPKP header using certificates in specified file or directory
  -flushCache       -- Flush specified caches in selected process, such as, lsass.exe
  -addEccCurve      -- Add ECC Curve
  -deleteEccCurve   -- Delete ECC Curve
  -displayEccCurve  -- Display ECC Curve
  -sign             -- Re-sign CRL or certificate

  -vroot            -- Create/delete web virtual roots and file shares
  -vocsproot        -- Create/delete web virtual roots for OCSP web proxy
  -addEnrollmentServer -- Add an Enrollment Server application
  -deleteEnrollmentServer -- Delete an Enrollment Server application
  -addPolicyServer  -- Add a Policy Server application
  -deletePolicyServer -- Delete a Policy Server application
  -oid              -- Display ObjectId or set display name
  -error            -- Display error code message text
  -getreg           -- Display registry value
  -setreg           -- Set registry value
  -delreg           -- Delete registry value

  -ImportKMS        -- Import user keys and certificates into server database for key archival
  -ImportCert       -- Import a certificate file into the database
  -GetKey           -- Retrieve archived private key recovery blob, generate a recovery script,
      or recover archived keys
  -RecoverKey       -- Recover archived private key
  -MergePFX         -- Merge PFX files

  -add-chain        -- (-AddChain) Add certificate chain
  -add-pre-chain    -- (-AddPrechain) Add pre-certificate chain
  -get-sth          -- (-GetSTH) Get signed tree head
  -get-sth-consistency -- (-GetSTHConsistency) Get signed tree head changes
  -get-proof-by-hash -- (-GetProofByHash) Get proof by hash
  -get-entries      -- (-GetEntries) Get entries
  -get-roots        -- (-GetRoots) Get roots
  -get-entry-and-proof -- (-GetEntryAndProof) Get entry and proof
  -VerifyCT         -- Verify certificate SCT
  -?                -- Display this usage message


CertUtil -?              -- Display a verb list (command list)
CertUtil -dump -?        -- Display help text for the "dump" verb
CertUtil -v -?           -- Display all help text for all verbs

CertUtil: -? command completed successfully.

.DESCRIPTION See help for C:\Windows\system32\certutil.exe

.PARAMETER CAFullName
Specify the Full Name of the Certificate Authority in the form 'FQDN\CA Name'


.PARAMETER GetReg
Specify AuditFilter



#>
}


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
function parseCertificateManager {
    param (
        $CertificateManager
    )

    [array] $CertificateManagerCollection = $CertificateManager | ForEach-Object {
        if ($_ -match '^.*Allow.*Certificate Manager.*?\s+([^\s\\]+\\.+)$') {
            [PSCustomObject]@{
                CertificateManager = $matches[1]
            }
        }
    }

    $CertificateManagerCollection
}
function parseEnrollmentAgent {
    param (
        $EnrollmentAgent
    )

    $EnrollmentAgentBlob = $EnrollmentAgent | Select-String '^0\w{3}\s+' | ForEach-Object {                                                
        ($_.ToString().substring(4) -replace '.{16}$', '').Replace(' ', '').Replace("`t", '')
    }

    $EnrollmentAgentByteArray = $EnrollmentAgentBlob -replace '\s+', '' -split '(?<=\G.{2})' | Where-Object { $_ } | ForEach-Object {
        [System.Convert]::ToByte($_, 16)
    }

    # Everything from here down is stolen shamelessly from Vadims Podāns (https://sysadmins.lv)
    $SecurityDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($EnrollmentAgentByteArray, 0)
    foreach ($commonAce in $SecurityDescriptor.DiscretionaryAcl) {
        # get ACE in binary form
        $aceBytes = New-Object byte[] -ArgumentList $commonAce.BinaryLength
        $commonAce.GetBinaryForm($aceBytes, 0)
        try {
            $EnrollmentAgent = $commonAce.SecurityIdentifier.translate([Security.Principal.NTAccount]).Value
        } catch {
            $EnrollmentAgent = $commonAce.SecurityIdentifier.Value
        }
        # set offset to application-specific data by skipping ACE header and
        # EnrollmentAgent's SID
        $offset = $commonAce.BinaryLength - $commonAce.OpaqueLength
        $SidCount = [BitConverter]::ToUInt32($aceBytes[$offset..($offset + 3)], 0)
        # initialize array to store array of securable principals
        $CanEnrollOnBehalfOf = @()
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
                $CanEnrollOnBehalfOf += $SID.translate([Security.Principal.NTAccount]).Value
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
            EnrollmentAgent     = $EnrollmentAgent
            AceType             = $commonAce.AceQualifier
            CanEnrollOnBehalfOf = $CanEnrollOnBehalfOf
            Template            = if ($oid) {
                if ([string]::IsNullOrEmpty($oid.FriendlyName)) { $oid.Value } else { $oid.FriendlyName }
            } else {
                "<Any>"
            }
        }
    }
}
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
function parseInterfaceFlag {
    param (
        $InterfaceFlag
    )

    [array]$InterfaceFlagCollection = $InterfaceFlag | ForEach-Object {
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
function parseAuditFilter {
    param (
        $CertutilAudit
    )
    # TODO: Translate AuditFilter to human-readable format
    try {
        [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = ' | Select-String '\('
        [int]$AuditFilter = $AuditFilter.split('(')[1].split(')')[0]
    } catch {
        try {
            [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = '
            [int]$AuditFilter = $AuditFilter.split('=')[1].trim()
        } catch {
            [int]$AuditFilter = $null
        }
    }
    [pscustomobject]@{
        AuditFilter = $AuditFilter
    }
}
