// Key Vault (RBAC mode) holding the application secrets. Container Apps read
// them at runtime through the backend's user-assigned managed identity.

param location string
param name string
param tags object

@description('Resource ID of the backend managed identity (stable seed for the role assignment name).')
param backendIdentityId string

@description('Principal (object) ID of the backend managed identity: gets Key Vault Secrets User on this vault.')
param backendPrincipalId string

@secure()
param databaseUrl string

@secure()
param postgresAdminPassword string

@secure()
param ingestApiToken string

@secure()
param adminPassword string

@secure()
param sessionSecret string

@secure()
@description('Fernet key encrypting notification channel secrets (webhook URLs, SMTP passwords) at rest.')
param notificationsEncryptionKey string
param mfaEncryptionKey string

// Built-in role: Key Vault Secrets User (read secret values).
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    // Data-plane access needs an Entra token plus an RBAC role on this vault.
    // See docs/DEPLOY_AZURE.md for locking it down further with a firewall.
    publicNetworkAccess: 'Enabled'
  }
}

var secrets = [
  {
    name: 'database-url'
    value: databaseUrl
  }
  {
    name: 'postgres-admin-password'
    value: postgresAdminPassword
  }
  {
    name: 'ingest-api-token'
    value: ingestApiToken
  }
  {
    name: 'admin-password'
    value: adminPassword
  }
  {
    name: 'session-secret'
    value: sessionSecret
  }
  {
    name: 'notifications-encryption-key'
    value: notificationsEncryptionKey
    name: 'mfa-encryption-key'
    value: mfaEncryptionKey
  }
]

resource secretResources 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = [
  for s in secrets: {
    parent: vault
    name: s.name
    properties: {
      value: s.value
      contentType: 'text/plain'
    }
  }
]

resource backendSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, backendIdentityId, keyVaultSecretsUserRoleId)
  scope: vault
  properties: {
    principalId: backendPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
  }
}

output name string = vault.name
output uri string = vault.properties.vaultUri
