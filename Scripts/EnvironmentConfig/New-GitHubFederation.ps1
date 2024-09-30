<#
        .SYNOPSIS
        Creates a federated identity credential between EntraID and GitHub that can be used to run Github actions.


        .DESCRIPTION
        Creates a federated identity credential between Azure Active Directory and GitHub that can be used to run Github actions.
        This is the prefered approach as there are no secrets or keys to secure or rotate.
        See the following documents for more details:
        https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure?tabs=azure-powershell%2Cwindows#use-the-azure-login-action-with-openid-connect
        This scripts creates the EntraID App Registration, Service Principal, and Group for the role assignment as well as creting Repository and Environment secrets in GitHub.

        The GitHub Fine-grained PAT needs the following Repository permissions:
        - Secrets: read, write
        - Environments: read, write
        - Variables: read, write
        - Metadata: read
        - Administration: read, write

        .EXAMPLE
        PS> New-GithubFerderation.ps1

        .EXAMPLE
        PS> New-GithubFerderation.ps1
#>

param (
    [String]
    $appName,
    $repo,
    $orgName,
    $tennant ,
    $groupName,
    $gitHubPat
)

Connect-AzAccount -Tenant $tennant

Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force
Install-Module -Name Az.Resources -AllowPrerelease -Scope CurrentUser -Force
Install-Module Microsoft.Graph -AllowPrerelease -Scope CurrentUser -Force
Install-Module -Name PowerShellForGitHub -Scope CurrentUser -Force


# create the Azure AD application that will be used for federation
New-AzADApplication -DisplayName $appName

#Create a service principal using the appid from the Azure AD Application
$clientId = (Get-AzADApplication -DisplayName $appName).AppId
New-AzADServicePrincipal -ApplicationId $clientId

# create a federated identity credential on an app
$objectId = (Get-AzADApplication -DisplayName $appName).Id
New-AzADAppFederatedCredential -ApplicationObjectId $objectId -Audience api://AzureADTokenExchange -Issuer 'https://token.actions.githubusercontent.com' -Name "$appName-Production" -Subject "repo:$($repo):environment:Production"
New-AzADAppFederatedCredential -ApplicationObjectId $objectId -Audience api://AzureADTokenExchange -Issuer 'https://token.actions.githubusercontent.com' -Name "$appName-Canary" -Subject "repo:$($repo):environment:Canary"
New-AzADAppFederatedCredential -ApplicationObjectId $objectId -Audience api://AzureADTokenExchange -Issuer 'https://token.actions.githubusercontent.com' -Name "$appName-PR" -Subject "repo:$($repo):pull_request"
New-AzADAppFederatedCredential -ApplicationObjectId $objectId -Audience api://AzureADTokenExchange -Issuer 'https://token.actions.githubusercontent.com' -Name "$appName-Main" -Subject "repo:$($repo):ref:refs/heads/main"

#authenticate to MS Graph
Connect-MgGraph -Scopes "Group.ReadWrite.All"

# create an EntraID gropup for the role assignment
$param = @{
    description=$groupName
    displayName=$groupName
    mailEnabled=$false
    securityEnabled=$true
    mailNickname=$groupName
   }
   
$entraIDGroup = New-MgGroup @param

# add user to group
$objectId = (Get-AzADServicePrincipal -DisplayName $appName).Id
New-MgGroupMember -GroupId $entraIDGroup.Id -DirectoryObjectId $objectId

# create a new role assignmnet - the service principal needs root contributor and ownwer in order to be able to create the Management Group structure
#New-AzRoleAssignment -ObjectId $entraIDGroup.Id -RoleDefinitionName Contributor -Scope /
New-AzRoleAssignment -ObjectId $entraIDGroup.Id -RoleDefinitionName Owner -Scope /




###TODO: Create GitHub Environments and Secrets

# create authentication header for GitHub

$authenticationToken = [System.Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$githubPat"))
    $headers = @{
        "Authorization" = [String]::Format("Basic {0}", $authenticationToken)
        "Content-Type"  = "application/json"
    }

# Get Repo Public Key 

$publicKeyAPIUri = "https://api.github.com/repos/$($repo)/actions/secrets/public-key"
$repoPublicKey = Invoke-RestMethod -Method get -Uri $publicKeyAPIUri -Headers $headers 


#Get the values for clientId, subscriptionId, and tenantId to use later in your GitHub Actions workflow.
$clientId = (Get-AzADApplication -DisplayName $appName).AppId
$subscriptionId = (Get-AzContext).Subscription.Id
$tenantId = (Get-AzContext).Subscription.TenantId


# encrypt the values for clientId, subscriptionId, and tenantId using the public key from GitHub.
$encClientId = ConvertTo-SodiumEncryptedString -PublicKey $repoPublicKey.key -Text $clientId
$enctenantId = ConvertTo-SodiumEncryptedString -PublicKey $repoPublicKey.key -Text  $tenantId

# create Repository secrets 
$data_encClientId = @{
    encrypted_value = $encClientId
    key_id = $repoPublicKey.key_id
}
$json_encClientId = $data_encClientId | ConvertTo-Json

$clientIdAPIUri = "https://api.github.com/repos/$($repo)/actions/secrets/AZURE_CLIENT_ID"
Invoke-RestMethod -Method PUT -Uri $clientIdAPIUri -Headers $headers -body $json_encClientId

$data_enctenantId = @{
    encrypted_value = $enctenantId
    key_id = $repoPublicKey.key_id
}
$json_enctenantId = $data_enctenantId | ConvertTo-Json

$tenantIdAPIUri = "https://api.github.com/repos/$($repo)/actions/secrets/AZURE_TENANT_ID"
Invoke-RestMethod -Method PUT -Uri $tenantIdAPIUri -Headers $headers -body $json_enctenantId


# create environments and environment secrets
$environments = @("Production", "Canary")
foreach ($environment in $environments) {
    $data_environment = @{}
    $json_enviornment = $data_environment | ConvertTo-Json
    $envionmentAPIURI = "https://api.github.com/repos/$($repo)/environments/$($environment)"
    Invoke-RestMethod -Method PUT -Uri $envionmentAPIURI -Headers $headers -body $json_enviornment
}

# Get environment encryption key
foreach ($environment in $environments) {

    $envPublicKeyAPIUri = "https://api.github.com/repos/$($repo)/environments/$($environment)/secrets/public-key"
    $envPublicKey = Invoke-RestMethod -Method get -Uri $envPublicKeyAPIUri -Headers $headers
    $encSubscritpionId = ConvertTo-SodiumEncryptedString -PublicKey $envPublicKey.key -Text $subscriptionId

    If($environment -eq "Production"){        
        $envSubIdAPIUri = "https://api.github.com/repos/$($repo)/environments/$($environment)/secrets/AZURE_MANAGEMENT_SUBSCRIPTION_ID"        
    }

    If($environment -eq "Canary"){
        $envSubIdAPIUri = "https://api.github.com/repos/$($repo)/environments/$($environment)/secrets/AZURE_MANAGEMENT_SUBSCRIPTION_ID"  
    }

    $envdata = @{
        encrypted_value = $encSubscritpionId 
        key_id = $envPublicKey.key_id
    }
    $envjson = $envdata | ConvertTo-Json
    Invoke-RestMethod -Method PUT -Uri $envSubIdAPIUri  -Headers $headers -body $envjson

}



