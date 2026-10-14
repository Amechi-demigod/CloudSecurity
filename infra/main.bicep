// CloudSecurity CNAPP on Azure - resource-group scoped deployment.
//
//   Internet --HTTPS--> Container App "web" (nginx + UI) --/api--> Container App "api" (internal)
//                                                                      |-- PostgreSQL Flexible Server (private, TLS)
//                                                                      |-- Key Vault (secrets via managed identity)
//                                                                      '-- Azure Resource Manager (read-only scanner, Reader role)
//
// Deployed by .github/workflows/deploy.yml with main.bicepparam. See docs/DEPLOY_AZURE.md.
targetScope = 'resourceGroup'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Short lowercase alphanumeric prefix for resource names (3-10 chars).')
@minLength(3)
@maxLength(10)
param namePrefix string = 'cnapp'

@description('Tags applied to every resource.')
param tags object = {
  app: 'cloudsecurity-cnapp'
  environment: 'production'
}

@description('Deploy the Container Apps. The workflow sets this to false only on the very first run, to create the registry before importing images.')
param deployApps bool = true

// --- application images --------------------------------------------------------
@description('Backend image (repository:tag) in the registry created here, e.g. cnapp-backend:<git sha>.')
param backendImage string = 'cnapp-backend:latest'

@description('Frontend image (repository:tag) in the registry created here.')
param frontendImage string = 'cnapp-frontend:latest'

// --- application settings ------------------------------------------------------
@description('E-mail of the first admin user (created on first start when no users exist).')
param adminEmail string

@description('Seed the simulated demo environment and run the event simulator.')
param simulationMode bool = true

@description('Comma-separated subscription IDs the Azure posture scanner reads (needs Reader for the backend identity).')
param scanSubscriptionIds string = ''

@description('CIDRs of the proxies in front of the backend (Container Apps ingress, web app). Only these may set X-Forwarded-For. Internet clients never have these addresses.')
param trustedProxyCidrs string = '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10'

// --- secrets (generated once by the deploy workflow, then read back from Key Vault) ---
@secure()
@minLength(16)
@description('PostgreSQL administrator password.')
param postgresAdminPassword string

@secure()
@minLength(32)
@description('Bearer token runtime sensors use for POST /api/runtime/events.')
param ingestApiToken string

@secure()
@minLength(12)
@description('Initial password of the first admin (change it after the first login).')
param adminPassword string

@secure()
@minLength(32)
@description('Key for session-token digests (SESSION_SECRET).')
param sessionSecret string

// --- sizing (low-cost demo defaults) ----------------------------------------------------
param postgresSkuName string = 'Standard_B1ms'
param postgresSkuTier string = 'Burstable'
param postgresStorageSizeGB int = 32
param postgresVersion string = '16'
param backendCpu string = '0.5'
param backendMemory string = '1Gi'
@minValue(1)
param backendMinReplicas int = 1
param backendMaxReplicas int = 2
param backendWorkers int = 2
@minValue(0)
param frontendMinReplicas int = 1
param frontendMaxReplicas int = 2
param logRetentionDays int = 30
@description('Log Analytics daily ingestion cap in GB (cost guard), as a string; "-1" disables the cap.')
param logDailyQuotaGb string = '0.5'

// --- network ---------------------------------------------------------------------------
param vnetAddressPrefix string = '10.42.0.0/16'
param appsSubnetPrefix string = '10.42.0.0/23'
param postgresSubnetPrefix string = '10.42.2.0/27'

var suffix = take(uniqueString(resourceGroup().id), 8)
var postgresAdminLogin = 'cnappadmin'
var databaseName = 'cnapp'

module network 'modules/network.bicep' = {
  name: 'network'
  params: {
    location: location
    namePrefix: namePrefix
    addressPrefix: vnetAddressPrefix
    appsSubnetPrefix: appsSubnetPrefix
    postgresSubnetPrefix: postgresSubnetPrefix
    tags: tags
  }
}

var logAnalyticsWorkspaceName = 'log-${namePrefix}'

module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: {
    location: location
    name: logAnalyticsWorkspaceName
    retentionInDays: logRetentionDays
    dailyQuotaGb: logDailyQuotaGb
    tags: tags
  }
}

// Backend identity: reads Key Vault secrets, pulls images, and is the identity
// the Azure posture scanner authenticates as (grant it Reader on subscriptions).
resource backendIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${namePrefix}-api'
  location: location
  tags: tags
}

// Frontend identity: image pulls only.
resource frontendIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${namePrefix}-web'
  location: location
  tags: tags
}

module registry 'modules/registry.bicep' = {
  name: 'registry'
  params: {
    location: location
    name: 'cr${namePrefix}${suffix}'
    tags: tags
    pullIdentities: [
      {
        id: backendIdentity.id
        principalId: backendIdentity.properties.principalId
      }
      {
        id: frontendIdentity.id
        principalId: frontendIdentity.properties.principalId
      }
    ]
  }
}

module postgres 'modules/postgres.bicep' = {
  name: 'postgres'
  params: {
    location: location
    name: 'psql-${namePrefix}-${suffix}'
    tags: tags
    delegatedSubnetId: network.outputs.postgresSubnetId
    vnetId: network.outputs.vnetId
    skuName: postgresSkuName
    skuTier: postgresSkuTier
    storageSizeGB: postgresStorageSizeGB
    postgresVersion: postgresVersion
    administratorLogin: postgresAdminLogin
    administratorLoginPassword: postgresAdminPassword
    databaseName: databaseName
  }
}

// verify-full: encrypted AND the server certificate/hostname are verified
// against the image's CA bundle (Debian ca-certificates).
var databaseUrl = 'postgresql://${postgresAdminLogin}:${uriComponent(postgresAdminPassword)}@${postgres.outputs.fqdn}:5432/${databaseName}?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca-certificates.crt'

module keyVault 'modules/keyvault.bicep' = {
  name: 'keyvault'
  params: {
    location: location
    name: 'kv-${namePrefix}-${suffix}'
    tags: tags
    backendIdentityId: backendIdentity.id
    backendPrincipalId: backendIdentity.properties.principalId
    databaseUrl: databaseUrl
    postgresAdminPassword: postgresAdminPassword
    ingestApiToken: ingestApiToken
    adminPassword: adminPassword
    sessionSecret: sessionSecret
  }
}

module apps 'modules/apps.bicep' = if (deployApps) {
  name: 'apps'
  params: {
    location: location
    namePrefix: namePrefix
    tags: tags
    infrastructureSubnetId: network.outputs.appsSubnetId
    logAnalyticsWorkspaceName: logAnalyticsWorkspaceName
    registryLoginServer: registry.outputs.loginServer
    keyVaultUri: keyVault.outputs.uri
    backendIdentityId: backendIdentity.id
    backendIdentityClientId: backendIdentity.properties.clientId
    frontendIdentityId: frontendIdentity.id
    backendImage: '${registry.outputs.loginServer}/${backendImage}'
    frontendImage: '${registry.outputs.loginServer}/${frontendImage}'
    adminEmail: adminEmail
    simulationMode: simulationMode
    scanSubscriptionIds: scanSubscriptionIds
    trustedProxyCidrs: trustedProxyCidrs
    backendCpu: backendCpu
    backendMemory: backendMemory
    backendMinReplicas: backendMinReplicas
    backendMaxReplicas: backendMaxReplicas
    backendWorkers: backendWorkers
    frontendMinReplicas: frontendMinReplicas
    frontendMaxReplicas: frontendMaxReplicas
  }
}

output registryName string = registry.outputs.name
output registryLoginServer string = registry.outputs.loginServer
output keyVaultName string = keyVault.outputs.name
output postgresServerName string = postgres.outputs.name
output postgresFqdn string = postgres.outputs.fqdn
output backendIdentityName string = backendIdentity.name
output backendIdentityPrincipalId string = backendIdentity.properties.principalId
output backendIdentityClientId string = backendIdentity.properties.clientId
output backendAppName string = deployApps ? apps!.outputs.backendAppName : ''
output frontendAppName string = deployApps ? apps!.outputs.frontendAppName : ''
output frontendUrl string = deployApps ? apps!.outputs.frontendUrl : ''
