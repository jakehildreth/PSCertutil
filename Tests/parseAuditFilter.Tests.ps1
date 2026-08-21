BeforeAll {
    # Load only the parser function under test — the module psm1 is Crescendo-generated
    # and importing it pulls in certutil.exe invocations we don't want in unit tests.
    $parserPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'parseAuditFilter.ps1'
    . $parserPath
}

Describe 'parseAuditFilter' -Tag 'Unit' {

    Context 'certutil succeeds — parenthesized decimal form' {
        # Typical output: AuditFilter REG_DWORD = 127 (0x7f)
        It 'should parse the decimal value from the parenthesized form' {
            $output = @(
                'AuditFilter REG_DWORD = 127 (0x7f)'
                'CertUtil: -getreg command completed successfully.'
            )
            $result = parseAuditFilter -CertutilAudit $output
            $result.AuditFilter | Should -Be 127
        }

        It 'should parse 0 as a real value, not a failure' {
            $output = @(
                'AuditFilter REG_DWORD = 0 (0x0)'
                'CertUtil: -getreg command completed successfully.'
            )
            $result = parseAuditFilter -CertutilAudit $output
            $result.AuditFilter | Should -Be 0
        }
    }

    Context 'certutil succeeds — bare decimal form (no hex suffix)' {
        It 'should parse the decimal value after the equals sign' {
            $output = @('AuditFilter REG_DWORD = 63')
            $result = parseAuditFilter -CertutilAudit $output
            $result.AuditFilter | Should -Be 63
        }
    }

    Context 'certutil fails (GH jakehildreth/Locksmith2 #92 root cause)' {
        # When the CA is unreachable, certutil emits error text with no AuditFilter line.
        # The parser must not fabricate a value: emitting AuditFilter=0 makes callers
        # report "auditing not enabled" on what was actually a query failure.
        It 'should emit nothing when the output contains no AuditFilter line' {
            $output = @(
                'CertUtil: -getreg command FAILED: 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE)'
                'CertUtil: The RPC server is unavailable.'
            )
            $result = parseAuditFilter -CertutilAudit $output
            $result | Should -BeNullOrEmpty
        }

        It 'should emit nothing when given empty output' {
            $result = parseAuditFilter -CertutilAudit @()
            $result | Should -BeNullOrEmpty
        }

        It 'should emit nothing when given null' {
            $result = parseAuditFilter -CertutilAudit $null
            $result | Should -BeNullOrEmpty
        }

        It 'must not return 0 on failure (0 is a real AuditFilter value meaning no auditing)' {
            $output = @('CertUtil: -getreg command FAILED: 0x800706ba')
            $result = parseAuditFilter -CertutilAudit $output
            if ($result) {
                $result.AuditFilter | Should -Not -Be 0 -Because 'a fabricated 0 is indistinguishable from auditing disabled'
            }
        }
    }
}
