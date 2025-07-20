# PSCertutil - A Powershell Wrapper for certutil.exe
Built w/ ❤️ and [Crescendo](https://github.com/PowerShell/Crescendo)

`certutil.exe` is a very old-school way to interact with Active Directory Certificate Services. It's shockingly powerful, but its output *sucks* to work with in PowerShell.

PSCertutil makes using `certutil.exe` a little more PowerShell-y:
* standard Verb-Noun function names
* common parameters
* structured output

It also provides some ready-made functions to get the most interesting pieces of information (read: stuff I needed to build for Locksmith 2).

*Note: This is an MVP, not a full-featured tool. There's almost no error handling and you can only check one CA at a time.*

## Installation

``` powershell
git clone https://github.com/jakehildreth/PSCertutil
Import-Module .\PSCertutil\PSCertutil.psd1
```

## Current Functions
* **Disable-PCEditFlag:** Disables the flags configured via the policy\EditFlags registry entry
* **Disable-PCInterfaceFlag:** Disables the flags configured via the CA\InterfaceFlags registry entry
* **Enable-PCEditFlag:** Enables the flags configured via the policy\EditFlags registry entry
* **Enable-PCInterfaceFlag:** Enables the flags configured via the CA\InterfaceFlags registry entry
* **Get-PCAuditFilter:** Gets the integer value that represents the bitmask that configures auditing on a CA. Used in Auditing checks. Will soon have human-readable output for auditing configuration.
* **Get-PCCAAdministrator:** Gets all principals granted the "CA Administrator" role on a CA. Used to perform ESC7 checks.
* **Get-PCCertificateManager:** Gets all principals granted "Certificate Manager" role on a CA. Used to perform ESC7 checks.
* **Get-PCDisableExtensionList:** Gets the policy\DisableExtensionList registry entry and returns objects for all disabled extensions. Used to perform ESC16 checks. Will soon have human-readable output for disabled extensions.
* **Get-PCDump:** Identical to "certutil -v -dump". Currently unparsed.
* **Get-PCEditFlag:** Gets the CA\EditFlags registry entry to display the current state of each edit flag. Used to perform ESC6 checks.
* **Get-PCEnrollmentAgent:** Gets Enrollment Agent configuration. Properly restricting Enrollment Agent rights can prevent ESC3 attacks.
* **Get-PCInterfaceFlag:** Gets the CA\InterfaceFlags registry entry to display the current state of each interface flag. Used to perform ESC11 checks.
* **Get-PCOfficerRight:** Gets Officer Rights configuration. Properly restricting Officer Rights can make a wide range of attacks more difficult.

## Future Functions
* **Get-PCRecentlyIssued**
* **Get-PCRecentlyFailed** 
* **Get-PCPendingRequests**/**Get-PCQueued**
* **Get-PCEffective**/**Get-PCActive**

## Thanks
* Brainstorming new functions: [@techSpence](https://github.com/techspence)
* Helping with 5.1 compatibility: [@steviecoaster](https://github.com/steviecoaster)
* AD CS ACL parsing logic: [@Crypt32](https://github.com/Crypt32)
