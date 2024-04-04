#requires -Modules @{ModuleName='AWS.Tools.IdentityManagement';ModuleVersion='4.1.540'}

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ProviderRegion,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [securestring]$ProviderIAMAccessKey,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [securestring]$ProviderIAMSecretAccessKey,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AnyIdentityIAMUserName = 'devolutions_anyidentity_provider_iam_access_key',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AnyIdentityIAMRoleName = 'IAMChangeAllAccessKeys',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PermissionBoundaryPolicyName = 'IAMChangeIAMAccessKeysPermissionBoundary',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RolePermissionPolicyName = 'IAMChangeIAMAccessKeysRole',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$UserPermissionPolicyName = 'IAMChangeIAMAccessKeysUserPolicy'
)

$ErrorActionPreference = 'Stop'

#region functions
function decryptPassword ([securestring]$Password) {
    # Decrypts a secure string password
    try {
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        ## Clear the decrypted password from memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function createPolicy($type, $name, $userArn) {
    try {
        $policyDoc = Get-Content -Path "$PSScriptRoot\policies\$type.json" -Raw
        if ($userArn) {
            $policyDoc = $policyDoc.replace('<user arn here>', $userArn)
        }
        New-IAMPolicy -PolicyName $name -PolicyDocument $policyDoc
    } catch [Amazon.IdentityManagement.Model.EntityAlreadyExistsException] {
        Write-Warning -Message "A policy named [$name] already exists."
        Get-IAMPolicies -Scope Local | Where-Object { $_.PolicyName -eq $name }
    }
}
#endregion

#region Authenticate to AWS using the IAM access key with permission to set up IAM user, access key and role
$initialAuthsetCredParams = @{
    AccessKey = (decryptPassword($ProviderIAMAccessKey))
    SecretKey = (decryptPassword($ProviderIAMSecretAccessKey))
    Scope     = 'Script'
}
Set-AWSCredential @initialAuthsetCredParams

Set-DefaultAWSRegion -Scope 'Script' -Region $ProviderRegion
#endregion

#region Create the Devolutions AnyIdentity account
try {
    $iamUser = Get-IAMUser -UserName $AnyIdentityIAMUserName
    Write-Warning -Message "An IAM user called [$AnyIdentityIAMUserName] already exists."
} catch [Amazon.IdentityManagement.Model.NoSuchEntityException] {
    $iamUser = New-IAMUser -UserName $AnyIdentityIAMUserName -Force
}
# #endregion

# #region Create an access key for the Devolutions AnyIdentity account

if (-not ($iamAccessKey = Get-IAMAccessKey -UserName $AnyIdentityIAMUserName)) {
    $iamAccessKey = New-IAMAccessKey -UserName $AnyIdentityIAMUserName
} else {
    Write-Warning -Message "The user [$($AnyIdentityIAMUserName)] already has an access key. AWS does not allow retrieving the secret access key from an existing key."
}
#endregion

#region Create the user policy and attach to the user
$userPolicy = createPolicy 'UserPermission' $UserPermissionPolicyName $iamUser.Arn
Register-IAMUserPolicy -PolicyArn $userPolicy.Arn -UserName $AnyIdentityIAMUserName
#endregion

#region Create the role permission policy and the role

#region Create the user role's permission boundary policy
$permissionsBoundary = createPolicy 'PermissionsBoundary' $PermissionBoundaryPolicyName
#endregion

$rolePermissionPolicy = createPolicy 'RolePermission' $RolePermissionPolicyName

try {
    $iamRole = Get-IAMRole -RoleName $AnyIdentityIAMRoleName
    Write-Warning -Message "An IAM role called [$AnyIdentityIAMRoleName] already exists."
} catch [Amazon.IdentityManagement.Model.NoSuchEntityException] {

    Write-Host 'Giving AWS a chance to catch up before creating role for 20 seconds...'
    Start-Sleep -Seconds 20
    $trustPolicy = (Get-Content -Path "$PSScriptRoot\policies\RoleTrust.json" -Raw).replace('<user arn here>', $iamUser.Arn)

    $newIamRoleParams = @{
        RoleName                 = $AnyIdentityIAMRoleName
        AssumeRolePolicyDocument = $trustPolicy
        PermissionsBoundary      = $permissionsBoundary.Arn
    }
    $iamRole = New-IAMRole @newIamRoleParams
    
} finally {
    Register-IAMRolePolicy -PolicyArn $rolePermissionPolicy.Arn -RoleName $AnyIdentityIAMRoleName
}
#endregion

#region Return all of the necessary attributes to use in the other provider scripts
[pscustomobject]@{
    UserAccessKeyId = $iamAccessKey.AccessKeyId
    UserSecretKey   = $iamAccessKey.SecretAccessKey
    RoleArn         = $iamRole.Arn
}
#endregion