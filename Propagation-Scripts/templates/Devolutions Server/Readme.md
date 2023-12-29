# Devolutions Hub Propagation Template

Here is the template to propagate a password to a secret in a Devolutions Server

## Parameters

| Parameter | Description |
|:----------|:------------|
|DevolutionsServerUrl       | Devolutions Server URL.                                                                                                           |
|ApplicationKey             | Application Key of the Application Identity created by an administrator in Devolutions Server                                     |
|ApplicationSecret          | Application secret of the Application Identity created by an administrator in Devolutions Server                                  |
|VaultId                    | Vault ID where the secret can be found. If vault ID is not provided, vault name will be used                                      |
|VaultName                  | Vault name used if the vault ID is not provided. The script will be more efficient with the vault ID.                             | 
|RunAsAccount               | The script is ran within a powershell remote session on the localhost. The session will be opened with that account if provided   |
|RunAsPassword              | If RunAsAccount is provided, this parameter is the password of the account used to open the remote session                        |
|PSSessionConfigurationName | If not specified, "Powershell.7" is used as configuration name to open the powershell remote session                              |