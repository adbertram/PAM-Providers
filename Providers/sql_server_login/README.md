# SQL Server Login AnyIdentity Provider

This SQL Server Login AnyIdentity provider is designed to integrate with the Devolutions Server PAM module to manage SQL Server login credentials. It enables automated account discovery and password rotation for SQL Server logins.

## Capabilities

This provider allows for:

- **Account Discovery**: Automated enumeration of SQL Server login accounts.
- **Heartbeat**: Validation that the passwords in Devolutions Server match those set on the SQL Server instance.
- **Password Rotation**: Automated update of SQL Server login passwords as per policy or on-demand.

## Prerequisites

Before using these scripts, ensure you meet the following prerequisites:

- Appropriate permissions on the SQL Server instance to query and modify login accounts.

You can run the included `sql_server_provider.prerequisites.tests.ps1` script against the SQL Server instance with intended user credentials to ensure all prerequisites are met.

## Account Discovery

The `account_discovery.ps1` script supports the discovery of SQL Server login accounts, enabling the Devolutions Server to manage these accounts effectively.

### Properties

| Property             | Description                                 | Mandatory | Example               |
|----------------------|---------------------------------------------|-----------|-----------------------|
| `SqlServerInstance`  | The SQL Server instance to connect to.      | Yes       | `"server.example.com"`|
| `SqlCredential`      | The PSCredential object for SQL authentication. | No    | `$(Get-Credential)`   |

## Heartbeat

The `heartbeat.ps1` script verifies that the passwords stored in Devolutions Server are synchronized with the SQL Server login passwords.

### Properties

| Property             | Description                                 | Mandatory | Example               |
|----------------------|---------------------------------------------|-----------|-----------------------|
| `SqlServerInstance`  | The SQL Server instance to connect to.      | Yes       | `"server.example.com"`|
| `SqlCredential`      | The PSCredential object for SQL authentication. | No    | `$(Get-Credential)`   |

## Password Rotation

The `password_rotation.ps1` script manages the rotation of SQL Server login passwords, ensuring compliance with security policies.

### Properties

| Property             | Description                                 | Mandatory | Example               |
|----------------------|---------------------------------------------|-----------|-----------------------|
| `SqlServerInstance`  | The SQL Server instance to connect to.      | Yes       | `"server.example.com"`|
| `SqlCredential`      | The PSCredential object for SQL authentication. | No    | `$(Get-Credential)`   |
| `NewPassword`        | The new password for the SQL login.         | Yes       | `"NewP@ssw0rd!"`      |

## Troubleshooting

- If the account discovery script does not return all expected accounts, verify that the SQL Server instance is accessible and that you have the necessary permissions.
- If password rotation fails, check for password complexity requirements or lockout policies that might be preventing the change.

If you need to troubleshoot the provider or are simply interested in seeing how the PowerShell scripts work under the hood, you can see an example on how to run the code below on a local SQL server instance.

```powershell
## Replace all instances of @sqlAuthCommonProviderParams with @windowsAuthCommonProviderParams if testing Windows Authentication
$sqlAuthCommonProviderParams = @{
    Server = 'localhost'
    ## Instance = ''
    ProviderSqlLoginUserName = '<username>'
    ProviderSqlLoginPassword = (Convertto-SecureString -String '<password>' -AsPlainText -Force)
    ## Port = 1433
}

## Uses the logged in Windows account to access the database
$windowsAuthCommonProviderParams = @{
    Server = 'localhost'
    ## Instance = ''
    ## Port = 1433
}

$accounts = .\account_discovery.ps1 @sqlAuthCommonProviderParams
$accountPwHashBefore = $accounts[4].secret

## SQL Server Login Heartbeat
## should return True because nothing changed
.\heartbeat.ps1 @sqlAuthCommonProviderParams -Secret $accountPwHashBefore -UserName $accounts[4].UserName

## SQL Server Login Password Rotation
## should return True
$someNewPassword = (Convertto-SecureString -String 'NewP@$$w0rd!!' -AsPlainText -Force)
.\password_rotation.ps1 @sqlAuthCommonProviderParams -UserName $accounts[4].UserName -NewPassword $someNewPassword

## Get the password hash now
$accounts = .\account_discovery.ps1 @sqlAuthCommonProviderParams
$accountPwHashAfter = $accounts[4].secret

## should return False because password changed and using old password
.\heartbeat.ps1 @sqlAuthCommonProviderParams -Secret $accountPwHashBefore -UserName $accounts[4].UserName

## should return True because password changed and using new password
.\heartbeat.ps1 @sqlAuthCommonProviderParams -Secret $accountPwHashAfter -UserName $accounts[4].UserName
```

## Additional Resources

For more information on managing SQL Server logins and PowerShell scripting, refer to the [official SQLServer module documentation](https://docs.microsoft.com/en-us/powershell/module/sqlserver/?view=sqlserver-ps).
