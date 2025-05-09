# PwshCertutil - A Powershell 7 Wrapper for certutil.exe
Built w/ ❤️ (and [Crescendo](https://github.com/PowerShell/Crescendo)) 

Current Cmdlets:
* **Get-PCAuditFilter:** Gets the integer value that represents the bitmask that configures auditing on a CA. Used in Auditing checks.
* **Get-PCCAAdministrator:** Gets all principals granted the "CA Administrator" role on a CA. Used to perform ESC7 checks.
* **Get-PCCertificateManager:** Gets all principals granted "Certificate Manager" role on a CA. Used to perform ESC7 checks.
* **Get-PCDump:** Identical to "certutil -v -dump". Currently unparsed.
* **Get-PCEditFlag:** Gets the CA\EditFlags registry entry to display the current state of each edit flag. Used to perform ESC6 checks.
* **Get-PCEnrollmentAgent:** Gets Enrollment Agent configuration. Properly restricting Enrollment Agent rights can prevent ESC3 attacks.
* **Get-PCInterfaceFlag:** Gets the CA\InterfaceFlags registry entry to display the current state of each interface flag. Used to perform ESC11 checks.
* **Get-PCOfficerRight:** Gets Officer Rights configuration. Properly restricting Officer Rights can make a wide range of attacks more difficult.