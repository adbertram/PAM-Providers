#requires ## modules with verisons here

[CmdletBinding()]
Param (
    ## must have parameters to provide an endpoint/server/something to connect to
    [Parameter(Mandatory)]
    [string]$Endpoint,

    [Parameter(Mandatory)]
    [string]$EndpointUserName, ## must have a way to pass credentials to the remote endpoint if not running over WinRM

    [Parameter(Mandatory)]
    [securestring]$EndpointPassword,  ## must have a way to pass credentials to the remote endpoint if not running over WinRM

    [Parameter(Mandatory)]
    [securestring]$Secret ## This MUST match the account_discovery output object property Secret and it's object type
)

$ErrorActionPreference = 'Stop'

## This is useful to see what parameters DVLS passed to the script
Write-Output -InputObject "Running script with parameters: $($PSBoundParameters | Out-String)"

try {

    
    ## TODO: should temporary access keys and long-terms keys be treated the same in this provider?
## You cannot get the secret key. need to figure out a way to get an access denied by forcing an action
    ## heartbeat scripts must return either a boolean $true value if Secret matches the current password or produce an error to the error stream

    
} catch {

} finally {

}