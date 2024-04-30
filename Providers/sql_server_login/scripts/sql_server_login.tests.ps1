#requires -Version 7
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0'}

<#
## Usage

SQL auth
------------------------
$parameters = @{
    ProviderEndpoint           = 'xxxxxxx'
    ProviderSqlLoginCredential = (New-Object System.Management.Automation.PSCredential ('<sql login UserName>', (ConvertTo-SecureString -String '<sql login password>' -AsPlainText -Force)))
    Port                       = 1433
    Instance                   = 'SQLEXPRESS'
}

Windows auth
------------------------
Not yet implemented

$container = New-PesterContainer -Path '<path>/<to>/sql_server_login.tests.ps1' -Data $parameters
Invoke-Pester -Container $container -Output Detailed

#>
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ProviderEndpoint,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Instance,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [int]$Port,

    [Parameter(ParameterSetName = 'SqlLogin')]
    [ValidateNotNullOrEmpty()]
    [pscredential]$ProviderSqlLoginCredential,

    [Parameter(ParameterSetName = 'WindowsAccount')]
    [ValidateNotNullOrEmpty()]
    [pscredential]$ProviderWindowsAccountCredential
)

BeforeAll {
    #region Create the testing artifacts

    function newConnectionString {
        $serverDetail = $ProviderEndpoint
        if ($Instance) {
            $serverDetail += "\$Instance"
        }
        if ($Port) {
            $serverDetail += ",$Port"
        }

        $connectionStringItems = @{
            'Database' = 'master'
            'Server'   = $serverDetail
        }

        if ($ProviderSqlLoginCredential) {
            ## Using SQL login to authenticate
            $userName = $ProviderSqlLoginCredential.UserName
            $password = $ProviderSqlLoginCredential.GetNetworkCredential().Password
            $connectionStringItems += @{
                'User ID'  = $userName
                'Password' = $password
            }
        } else {
            ## using the currently logged in user via Windows auth to authenticate
            $connectionStringItems += @{
                'Integrated Security' = 'True'
            }
        }
        ($connectionStringItems.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ";"
    }

    function invokeSqlQuery {
        param(
            $Connection,
            [string]$Query
        )
        try {
    
            # Execute the query
            $command = $Connection.CreateCommand()
            $command.CommandText = $Query
    
            # Execute the command and process the results
            $reader = $command.ExecuteReader()
            while ($reader.Read()) {
                [PSCustomObject]@{
                    'name'          = $reader['name']
                    'password_hash' = $reader['password_hash']
                }
            }
        } finally {
            if ($reader) {
                $reader.Close()
            }
        }
    }

    if ($ProviderSqlLoginCredential) {
        #region Create the SQL login
        $testLoginName = 'testingsqllogin'
        $testLoginPassword = $ProviderSqlLoginCredential.GetNetworkCredential().Password

        $connectionString = newConnectionString
        $connection = New-Object System.Data.SqlClient.SqlConnection $connectionString

        try {
            $connection.Open()
            $command = $connection.CreateCommand()
            $command.CommandText = "IF EXISTS (SELECT * FROM sys.server_principals WHERE name = N'$testLoginName')
                                BEGIN
                                    ALTER LOGIN [$testLoginName] WITH PASSWORD = '$testLoginPassword';
                                END
                            ELSE
                                BEGIN
                                    CREATE LOGIN [$testLoginName] WITH PASSWORD = '$testLoginPassword';
                                END"
            $command.ExecuteNonQuery()
        } catch {
            Write-Error "Failed to create SQL login: $_"
        }
        #endregion

        ## Get the new SQL login's password hash
        $sqlLogin = invokeSqlQuery -Connection $connection -Query "SELECT name, password_hash FROM sys.sql_logins;"
        $script:sqlLoginPwHashBefore = $sqlLogin.password_hash -join ''
    } else {
        throw 'not implemented'
    }
    #endregion
}

AfterAll {
    #region Cleanup of test SQL login
    if ($command -and $connection.State -eq 'Open') {
        $command.CommandText = "IF EXISTS (SELECT * FROM sys.sql_logins WHERE name = '$testLoginName') DROP LOGIN [$testLoginName]"
        $command.ExecuteNonQuery()
        $connection.Close()
    }
    #endregion
}

# Describe 'documentation' {
#     It 'the provider has a README file' {
#         $readmePath = Join-Path -Path ($PSScriptRoot | Split-Path -Parent) -ChildPath 'README.md'
#         Test-Path -Path $readmePath | Should -BeTrue
#     }
# }

Describe 'prereqs' {

    BeforeAll {
        $prereqParams = @{
            Endpoint = $ProviderEndpoint
            Port     = $Port ? $Port : 1433
        }
        if ($Instance) {
            $prereqParams.InstanceName = $Instance
        }
    
        if ($ProviderSqlLoginCredential) {
            $prereqParams.SqlLoginCredential = $ProviderSqlLoginCredential
        } else {
            $prereqParams.WindowsAccountCredential = $ProviderWindowsAccountCredential
        }
    }

    It 'passes all infrastruture prereq tests' {
        $result = & "$PSScriptRoot\sql_server_login.prerequisites.tests.ps1" @prereqParams
        $result | Should -BeTrue
    }
}

Describe 'account discovery' {

    it 'must return an object with the id, UserName, and secret properties' {
        $result = & "$PSScriptRoot\account_discovery.ps1" /////
        $result | Should -BeOfType [pscustomobject]
        $result.id | Should -BeOfType [string]
        $result.UserName | Should -BeOfType [string]
        $result.secret | Should -BeOfType [securestring]
    }

    Context 'SQL authentication' {

        BeforeAll {

            if ($ProviderSqlLoginCredential) {
                $tests = @{
                    output         = @(
                        @{
                            parameter_set   = @{
                                Server                   = $ProviderEndpoint
                                Port                     = $Port
                                Instance                 = $Instance
                                ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
                                ProviderSqlLoginPassword = (ConvertTo-SecureString -AsPlainText $ProviderSqlLoginCredential.GetNetworkCredential().Password -Force)
                            }
                            expected_output = @(
                                [pscustomobject]@{
                                    id       = $testLoginName
                                    UserName = $testLoginName
                                    secret   = $script:sqlLoginPwHashBefore
                                }
                            )
                        }
                    )
                    error_handling = @(
                        @{
                            parameter_set          = @{
                                Server                   = $ProviderEndpoint
                                Port                     = $Port
                                Instance                 = $Instance
                                ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
                            }
                            expected_error_message = 'You must use the ProviderSqlLoginUserName and ProviderSqlLoginPassword parameters at the same time.'
                        }
                        @{
                            parameter_set          = @{
                                Server                   = $ProviderEndpoint
                                Port                     = $Port
                                Instance                 = $Instance
                                ProviderSqlLoginPassword = (ConvertTo-SecureString -AsPlainText $ProviderSqlLoginCredential.GetNetworkCredential().Password -Force)
                            }
                            expected_error_message = 'You must use the ProviderSqlLoginUserName and ProviderSqlLoginPassword parameters at the same time.'
                        }
                        @{
                            parameter_set          = @{
                                Server                   = $ProviderEndpoint
                                Port                     = $Port
                                Instance                 = $Instance
                                ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
                                ProviderSqlLoginPassword = (ConvertTo-SecureString -AsPlainText $ProviderSqlLoginCredential.GetNetworkCredential().Password -Force)
                            }
                            expected_error_message = '*The server was not found or was not accessible*'
                        }
                    )
                }
            }
        }

        It "returns the expected users for params: <parameter_set.Keys>" -ForEach $tests.output {

            $foo = ''
            $result = & "$PSScriptRoot\account_discovery.ps1" @parameter_set
            $testUser = $result.where({ $_.id -eq $expected_output[0].UserName })
            $testUser | Should -Not -BeNullOrEmpty
                    
            $testUser.UserName | Should -Be $expected_output[0].UserName
            $testUser.secret | Should -Be $expected_output[0].secret
        }

        It 'throws an expected error for params: <parameter_set.Keys>' -ForEach $tests.error_handling {
            
            { & "$PSScriptRoot\account_discovery.ps1" @parameter_set } | Should -Throw $expected_error_message

        }
    }

    # Context 'Windows authentication' {

    #     if (!$ProviderSqlLoginCredential) {
    #         $tests = @{
    #             output         = @(
    #                 @{
    #                     parameter_set   = @{
    #                         Server   = $ProviderEndpoint
    #                         Port     = $Port
    #                         Instance = $Instance
    #                     }
    #                     expected_output = @(
    #                         [pscustomobject]@{
    #                             id       = $testLoginName
    #                             UserName = $testLoginName
    #                             secret   = $Secret
    #                         }
    #                     )
    #                 }
    #             )
    #             error_handling = @(
    #                 @{
    #                     parameter_set          = @{
    #                         Server   = 'somebogusserver'
    #                         Port     = $Port
    #                         Instance = $Instance
    #                     }
    #                     expected_error_message = '*The server was not found or was not accessible*'
    #                 }
    #             )
    #         }

    #         It "returns the expected users for params: <parameter_set.Keys>" -ForEach $tests.output {

    #             $result = & "$PSScriptRoot\account_discovery.ps1" @parameter_set

    #             $result[0].id | Should -Be $expected_output[0].id
    #             $result[0].UserName | Should -Be $expected_output[0].UserName
    #             $result[0].secret | Should -Be $expected_output[0].secret

    #         }

    #         It 'throws an expected error for params: <parameter_set.Keys>' -ForEach $tests.error_handling {
            
    #             { & "$PSScriptRoot\account_discovery.ps1" @parameter_set } | Should -Throw $expected_error_message

    #         }
    #     }
    # }
}

# Describe 'heartbeat' {

#     Context 'SQL authentication' {

#         if ($ProviderSqlLoginCredential) {

#             $tests = @{
#                 output         = @(
#                     @{
#                         parameter_set   = @{
#                             Server                   = $ProviderEndpoint
#                             Port                     = $Port
#                             Instance                 = $Instance
#                             ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
#                             ProviderSqlLoginPassword = (ConvertTo-SecureString -AsPlainText $ProviderSqlLoginCredential.GetNetworkCredential().Password -Force)
#                             UserName                 = $testLoginName
#                             Secret                   = $Secret
#                         }
#                         expected_output = $true
#                     },
#                     @{
#                         parameter_set   = @{
#                             Server                   = $ProviderEndpoint
#                             Port                     = $Port
#                             Instance                 = $Instance
#                             ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
#                             ProviderSqlLoginPassword = (ConvertTo-SecureString -AsPlainText $ProviderSqlLoginCredential.GetNetworkCredential().Password -Force)
#                             UserName                 = $testLoginName
#                             Secret                   = '<something different than what the password hash currently is>'
#                         }
#                         expected_output = $false
#                     }
#                 )
#                 error_handling = @(
#                     @{
#                         parameter_set          = @{
#                             Server                   = $ProviderEndpoint
#                             Port                     = $Port
#                             Instance                 = $Instance
#                             ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
#                             UserName                 = $testLoginName
#                             Secret                   = $Secret
#                         }
#                         expected_error_message = 'You must use the ProviderSqlLoginUserName and ProviderSqlLoginPassword parameters at the same time.'
#                     }
#                     @{
#                         parameter_set          = @{
#                             Server                   = $ProviderEndpoint
#                             Port                     = $Port
#                             Instance                 = $Instance
#                             ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
#                             UserName                 = $testLoginName
#                             Secret                   = $Secret
#                         }
#                         expected_error_message = 'You must use the ProviderSqlLoginUserName and ProviderSqlLoginPassword parameters at the same time.'
#                     }
#                     @{
#                         parameter_set          = @{
#                             Server                   = 'somebogusserver'
#                             Port                     = $Port
#                             Instance                 = $Instance
#                             ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
#                             ProviderSqlLoginPassword = (ConvertTo-SecureString -AsPlainText $ProviderSqlLoginCredential.GetNetworkCredential().Password -Force)
#                             UserName                 = $testLoginName
#                             Secret                   = $Secret
#                         }
#                         expected_error_message = '*The server was not found or was not accessible*'
#                     }
#                 )
#             }

#             It "returns the expected output for params: <parameter_set.Keys>" -ForEach $tests.output {

#                 $result = & "$PSScriptRoot\heartbeat.ps1" @parameter_set

#                 $result | Should -Be $expected_output
#             }

#             It 'throws an expected error for params: <parameter_set.Keys>' -ForEach $tests.error_handling {
            
#                 { & "$PSScriptRoot\heartbeat.ps1" @parameter_set } | Should -Throw $expected_error_message

#             }
#         }
#     }

#     Context 'Windows authentication' {

#         if (!$ProviderSqlLoginCredential) {
#             $tests = @{
#                 output         = @(
#                     @{
#                         parameter_set   = @{
#                             Server   = $ProviderEndpoint
#                             Port     = $Port
#                             Instance = $Instance
#                             UserName = $UserName
#                             Secret   = $Secret
#                         }
#                         expected_output = $true
#                     },
#                     @{
#                         parameter_set   = @{
#                             Server   = $ProviderEndpoint
#                             Port     = $Port
#                             Instance = $Instance
#                             UserName = $UserName
#                             Secret   = '<something different than what the password hash currently is>'
#                         }
#                         expected_output = $false
#                     }
#                 )
#                 error_handling = @(
#                     @{
#                         parameter_set          = @{
#                             Server   = 'somebogusserver'
#                             Port     = $Port
#                             Instance = $Instance
#                             UserName = $UserName
#                             Secret   = $Secret
#                         }
#                         expected_error_message = '*The server was not found or was not accessible*'
#                     }
#                 )
#             }

#             It "returns the expected output for params: <parameter_set.Keys>" -ForEach $tests.output {

#                 $result = & "$PSScriptRoot\heartbeat.ps1" @parameter_set

#                 $result | Should -Be $expected_output
#             }

#             It 'throws an expected error for params: <parameter_set.Keys>' -ForEach $tests.error_handling {
            
#                 { & "$PSScriptRoot\heartbeat.ps1" @parameter_set } | Should -Throw $expected_error_message

#             }
#         }
#     }
# }

# Describe 'password rotation' {

#     ## Don't actually change the password
#     Mock 'invokeSqlQuery'

#     Context 'SQL authentication' {

#         if ($ProviderSqlLoginCredential) {

#             $tests = @{
#                 output         = @(
#                     @{
#                         parameter_set   = @{
#                             Server                   = $ProviderEndpoint
#                             Port                     = $Port
#                             Instance                 = $Instance
#                             ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
#                             ProviderSqlLoginPassword = (ConvertTo-SecureString -AsPlainText $ProviderSqlLoginCredential.GetNetworkCredential().Password -Force)
#                             UserName                 = $testLoginName
#                             NewPassword              = $NewPassword
#                         }
#                         expected_output = $true
#                     },
#                     @{
#                         parameter_set   = @{
#                             Server                   = $ProviderEndpoint
#                             Port                     = $Port
#                             Instance                 = $Instance
#                             ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
#                             ProviderSqlLoginPassword = (ConvertTo-SecureString -AsPlainText $ProviderSqlLoginCredential.GetNetworkCredential().Password -Force)
#                             UserName                 = $testLoginName
#                             NewPassword              = $NewPassword
#                         }
#                         expected_output = $false
#                     }
#                 )
#                 error_handling = @(
#                     @{
#                         parameter_set          = @{
#                             Server                   = $ProviderEndpoint
#                             Port                     = $Port
#                             Instance                 = $Instance
#                             ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
#                             UserName                 = $testLoginName
#                             NewPassword              = $NewPassword
#                         }
#                         expected_error_message = 'You must use the ProviderSqlLoginUserName and ProviderSqlLoginPassword parameters at the same time.'
#                     }
#                     @{
#                         parameter_set          = @{
#                             Server                   = $ProviderEndpoint
#                             Port                     = $Port
#                             Instance                 = $Instance
#                             ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
#                             UserName                 = $testLoginName
#                             NewPassword              = $NewPassword
#                         }
#                         expected_error_message = 'You must use the ProviderSqlLoginUserName and ProviderSqlLoginPassword parameters at the same time.'
#                     }
#                     @{
#                         parameter_set          = @{
#                             Server                   = 'somebogusserver'
#                             Port                     = $Port
#                             Instance                 = $Instance
#                             ProviderSqlLoginUserName = $ProviderSqlLoginCredential.UserName
#                             ProviderSqlLoginPassword = (ConvertTo-SecureString -AsPlainText $ProviderSqlLoginCredential.GetNetworkCredential().Password -Force)
#                             UserName                 = $testLoginName
#                             NewPassword              = $NewPassword
#                         }
#                         expected_error_message = '*The server was not found or was not accessible*'
#                     }
#                 )
#             }

#             It "returns the expected output for params: <parameter_set.Keys>" -ForEach $tests.output {

#                 $result = & "$PSScriptRoot\password_rotation.ps1" @parameter_set

#                 $result | Should -Be $expected_output
#             }

#             It 'throws an expected error for params: <parameter_set.Keys>' -ForEach $tests.error_handling {
            
#                 { & "$PSScriptRoot\password_rotation.ps1" @parameter_set } | Should -Throw $expected_error_message

#             }
#         }
#     }

#     Context 'Windows authentication' {

#         if (!$ProviderSqlLoginCredential) {
#             $tests = @{
#                 output         = @(
#                     @{
#                         parameter_set   = @{
#                             Server      = $ProviderEndpoint
#                             Port        = $Port
#                             Instance    = $Instance
#                             UserName    = $UserName
#                             NewPassword = $NewPassword
#                         }
#                         expected_output = $true
#                     }
#                 )
#                 error_handling = @(
#                     @{
#                         parameter_set          = @{
#                             Server      = 'somebogusserver'
#                             Port        = $Port
#                             Instance    = $Instance
#                             UserName    = $UserName
#                             NewPassword = $NewPassword
#                         }
#                         expected_error_message = '*The server was not found or was not accessible*'
#                     }
#                 )
#             }

#             It "returns the expected output for params: <parameter_set.Keys>" -ForEach $tests.output {

#                 $result = & "$PSScriptRoot\password_rotation.ps1" @parameter_set

#                 $result | Should -Be $expected_output
#             }

#             It 'throws an expected error for params: <parameter_set.Keys>' -ForEach $tests.error_handling {
            
#                 { & "$PSScriptRoot\password_rotation.ps1" @parameter_set } | Should -Throw $expected_error_message

#             }
#         }
#     }
# }