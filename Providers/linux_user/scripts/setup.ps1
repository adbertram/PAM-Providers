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
    [string]$LinuxHostUserName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [securestring]$LinuxHostPassword
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
    $sshKeyAlgo = 'ed25519'
    ## https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement
    Start-Process 'ssh-keygen' -ArgumentList "-f `"$sshKeyPath`" -t $sshKeyAlgo -N `"`"" -NoNewWindow -Wait
    
    #endregion
    
    #region Copy the public key to the remote Linux host and private key to the DVLS server
    
    ## public key
    $publicKeyContents = Get-Content -Path "$sshKeyPath.pub"
    ssh $LinuxHostUserName@$LinuxHostName "echo '$publicKeyContents' >> ~/.ssh/authorized_keys"
    
    ## private key
    $psSession = New-PSSession -ComputerName $DvlsServerHostName -Credential $DvlServerCredential
    Copy-Item -ToSession $psSession -Path $sshKeyPath -Destination 'C:\'
    #endregion

    #region Protect the remote private key by...
    
    Invoke-Command -Session $psSession -ScriptBlock {

        icacls $using:sshKeyPath /inheritance:r
        icacls $using:sshKeyPath /grant:r "NT AUTHORITY\NETWORK SERVICE:(R)"

        Set-Service -Name "ssh-agent" -StartupType Manual
        Start-Service ssh-agent
        ssh-add $using:sshKeyPath
    
    } -Credential $DvlServerCredential

    $psSession | Remove-PSSession
    #endregion
    
    
    
    # Connect to the Linux host via SSH using the private key from the Windows Certificate Store
    ssh -i cert://$($cert.Thumbprint) $linuxUsername@$linuxHostIp
    #endregion
} catch {
    $PSCmdlet.ThrowTerminatingError($_)
} finally {
    Remove-Item -Path "$sshKeyPath\*" -Recurse
}