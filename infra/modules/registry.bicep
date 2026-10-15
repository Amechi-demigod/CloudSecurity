// Azure Container Registry (Basic). The deploy workflow imports the images CI
// pushed to ghcr.io; Container Apps pull with managed identities (no admin
// user, no registry passwords).

param location string
param name string
param tags object

@description('Managed identities that get AcrPull on the registry: [{ id: <resource id>, principalId: <object id> }].')
param pullIdentities array

// Built-in role: AcrPull.
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
  }
}

resource pull 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for identity in pullIdentities: {
    name: guid(registry.id, identity.id, acrPullRoleId)
    scope: registry
    properties: {
      principalId: identity.principalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    }
  }
]

output name string = registry.name
output loginServer string = registry.properties.loginServer
