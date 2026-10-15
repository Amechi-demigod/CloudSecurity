// Log Analytics workspace for Container Apps console/system logs.

param location string
param name string

@description('Days to keep logs (30 is included in the per-GB price).')
@minValue(30)
@maxValue(730)
param retentionInDays int

@description('Daily ingestion cap in GB (cost guard). -1 = no cap.')
param dailyQuotaGb string

param tags object

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: json(dailyQuotaGb)
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

output workspaceName string = workspace.name
output workspaceId string = workspace.id
