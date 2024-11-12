targetScope = 'subscription'

metadata name = 'Using large parameter set'
metadata description = 'This instance deploys the module with most of its features enabled.'

// ========== //
// Parameters //
// ========== //

@description('Optional. The location to deploy resources to.')
param resourceLocation string = deployment().location

@description('Optional. A short identifier for the kind of deployment. Should be kept short to not run into resource-name length-constraints.')
param serviceShort string = 'rrgmax'

@description('Optional. A token to inject into the name of each resource.')
param namePrefix string = '_psrules_'

// ============ //
// Dependencies //
// ============ //

// General resources
// =================

// ============== //
// Test Execution //
// ============== //

module testDeployment 'main.tests.bicep' = {
  name: '${uniqueString(deployment().name, resourceLocation)}-test-${serviceShort}'
  params: {
    location: resourceLocation
    name: 'avm-${namePrefix}-resources.resourcegroups-${serviceShort}-rg'
    lock: {
      kind: 'CanNotDelete'
      name: 'myCustomLockName'
    }
    tags: {
      'hidden-title': 'This is visible in the resource name'
      Environment: 'Non-Prod'
      Role: 'DeploymentValidation'
    }
  }
}
