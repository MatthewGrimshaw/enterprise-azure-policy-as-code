targetScope = 'managementGroup'

param location string = deployment().location
param managementSubscriptionId string
param resourceGroupName string
param tags object


// Create a resource group

module group 'resource-group.resource.bicep' = {
  scope: subscription(managementSubscriptionId)
  name: 'resource-group-${uniqueString(resourceGroupName)}'
  params: {
    location: location
    name: resourceGroupName
    lock: {
      kind: 'CanNotDelete'
      name: '${resourceGroupName}-resource-group-lock'   
    }
    tags: tags
  }
}
