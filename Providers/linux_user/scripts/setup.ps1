## Steps to be perform on an outside host (outside of DVLS)

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DvlsServerHostName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [pscredential]$DvlServerCredential,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$LinuxHostName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$LinuxHostUserName
)

#region Test for and install the OpenSSH client if it doesn't exist on the local machine
if (-not (Get-WindowsCapability -Online | Where-Object Name -Like 'OpenSSH.Client*').State -eq 'Installed') {
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
}
#endregion

try {
    #region Generate the SSH key pair locally
    
    $sshKeyName = 'dvls-linux-user'
    $sshKeyPath = (Join-Path -Path $PSScriptRoot -ChildPath $sshKeyName)
    # $sshKeyAlgo = 'ed25519'
    # ## https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement
    # $null = Start-Process 'ssh-keygen' -ArgumentList "-f `"$sshKeyPath`" -t $sshKeyAlgo -N `"`"" -NoNewWindow -Wait
    
    #endregion
    
    #region Copy the public key to the remote Linux host and private key to the DVLS server
    ## This could be better using keys
    
    ## public key
    # $publicKeyContents = Get-Content -Path "$sshKeyPath.pub"
    # Write-Host 'Provide the Linux host user password to copy the public key to.'
    # ssh $LinuxHostUserName@$LinuxHostName "echo '$publicKeyContents' >> ~/.ssh/authorized_keys"
    
    ## private key
    $psSession = New-PSSession -ComputerName $DvlsServerHostName -Credential $DvlServerCredential
    Copy-Item -ToSession $psSession -Path $sshKeyPath -Destination 'C:\'
    #endregion

    # #region Protect the private key on the DVLS server by adding it to the SSH agent
    
    Invoke-Command -Session $psSession -ScriptBlock {
        
        # Explicitly reset permissions, remove all inherited permissions, and grant read access to only the specified user

        TakeOwn /F $using:sshKeyPath
        # icacls $using:sshKeyPath /reset
        # icacls $using:sshKeyPath /inheritance:r
        # icacls $using:sshKeyPath /remove:g "Authenticated Users"
        # icacls $using:sshKeyPath /remove:g "Users"
        # icacls $using:sshKeyPath /grant:r "$($env:USERNAME):(R)"
    
        # Check the permissions after setting
        # icacls $using:sshKeyPath
    
        # # Attempt to start and communicate with the SSH agent
        # Set-Service -Name "ssh-agent" -StartupType Manual
        # Start-Service ssh-agent
        # ssh-add $using:sshKeyPath
    }
    
    

    # #endregion
} catch {
    throw $_
} finally {
    ## Remove the private and public key from the local machine
    Remove-Item -Path "$sshKeyPath`*" 

    ## Close the session
    $psSession | Remove-PSSession
}