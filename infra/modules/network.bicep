// Virtual network for the Container Apps environment and a delegated subnet
// for PostgreSQL Flexible Server (private access: no public endpoint).

@description('Azure region.')
param location string

@description('Resource name prefix.')
param namePrefix string

@description('Address space of the virtual network.')
param addressPrefix string

@description('Subnet for the Container Apps environment (workload profiles: /27 or larger).')
param appsSubnetPrefix string

@description('Subnet delegated to PostgreSQL Flexible Server.')
param postgresSubnetPrefix string

param tags object

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'vnet-${namePrefix}'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        addressPrefix
      ]
    }
    subnets: [
      {
        name: 'snet-apps'
        properties: {
          addressPrefix: appsSubnetPrefix
          delegations: [
            {
              name: 'containerapps'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'snet-postgres'
        properties: {
          addressPrefix: postgresSubnetPrefix
          delegations: [
            {
              name: 'postgres'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
    ]
  }
}

output vnetId string = vnet.id
output appsSubnetId string = vnet.properties.subnets[0].id
output postgresSubnetId string = vnet.properties.subnets[1].id
