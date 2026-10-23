// Container Apps environment (VNet-integrated, Consumption workload profile)
// with two apps:
//   * web  - nginx serving the UI; the only public endpoint (HTTPS, managed
//            certificate). It proxies /api/ to the backend, so the browser
//            sees one origin and the session cookie stays same-origin.
//   * api  - FastAPI backend; internal ingress only (reachable from inside
//            the environment, never from the internet). Secrets come from Key
//            Vault through its user-assigned managed identity, which is also
//            the identity the Azure posture scanner uses.

param location string
param namePrefix string
param tags object

param infrastructureSubnetId string
param logAnalyticsWorkspaceName string

param registryLoginServer string
param keyVaultUri string

@description('Resource ID of the backend user-assigned managed identity.')
param backendIdentityId string

@description('Client ID of the backend user-assigned managed identity.')
param backendIdentityClientId string

@description('Resource ID of the frontend user-assigned managed identity (image pulls only).')
param frontendIdentityId string

param backendImage string
param frontendImage string

param adminEmail string
param simulationMode bool
param scanSubscriptionIds string
param trustedProxyCidrs string

@description('Public URL of the web UI for notification deep links; empty = the web app URL.')
param publicBaseUrl string = ''

@description('MFA / Microsoft Entra ID sign-in settings (see main.bicep and docs/AUTH.md).')
param auth object

param backendCpu string
param backendMemory string
param backendMinReplicas int
param backendMaxReplicas int
param backendWorkers int
param frontendMinReplicas int
param frontendMaxReplicas int

var backendName = '${namePrefix}-api'
var frontendName = '${namePrefix}-web'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsWorkspaceName
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cae-${namePrefix}'
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: workspace.properties.customerId
        sharedKey: workspace.listKeys().primarySharedKey
      }
    }
    vnetConfiguration: {
      infrastructureSubnetId: infrastructureSubnetId
      internal: false
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
    zoneRedundant: false
  }
}

var frontendOrigin = 'https://${frontendName}.${env.properties.defaultDomain}'
var notificationsBaseUrl = empty(publicBaseUrl) ? frontendOrigin : publicBaseUrl

var kvSecret = union({
  'database-url': 'database-url'
  'ingest-api-token': 'ingest-api-token'
  'admin-password': 'admin-password'
  'session-secret': 'session-secret'
  'notifications-encryption-key': 'notifications-encryption-key'
  'mfa-encryption-key': 'mfa-encryption-key'
}, empty(auth.entraCredentialSecretName) ? {} : {
  // Entra client secret or certificate (PEM), stored in Key Vault by you (docs/AUTH.md).
  'entra-client-credential': auth.entraCredentialSecretName
})

// Redirect URI to register on the Entra application (also an output).
var entraRedirectUri = '${frontendOrigin}/api/auth/sso/entra/callback'

var authEnv = concat([
  { name: 'MFA_ENCRYPTION_KEY', secretRef: 'mfa-encryption-key' }
  { name: 'MFA_REQUIRED_ROLES', value: auth.mfaRequiredRoles }
  { name: 'AUTH_PASSWORD_LOGIN_ENABLED', value: string(auth.passwordLoginEnabled) }
  { name: 'AUTH_BREAK_GLASS_EMAILS', value: empty(auth.breakGlassEmails) ? adminEmail : auth.breakGlassEmails }
], empty(auth.entraClientId) ? [] : [
  { name: 'ENTRA_TENANT_ID', value: auth.entraTenantId }
  { name: 'ENTRA_CLIENT_ID', value: auth.entraClientId }
  // managed_identity: the backend identity is a federated credential of the app (no secret).
  { name: 'ENTRA_CLIENT_AUTH', value: auth.entraClientAuth }
  { name: 'ENTRA_MANAGED_IDENTITY_CLIENT_ID', value: backendIdentityClientId }
  { name: 'ENTRA_REDIRECT_URI', value: entraRedirectUri }
  { name: 'ENTRA_ROLE_MAP', value: auth.entraRoleMap }
  { name: 'ENTRA_JIT_PROVISIONING', value: string(auth.entraJitProvisioning) }
  { name: 'ENTRA_DEFAULT_ROLE', value: auth.entraDefaultRole }
], empty(auth.entraCredentialSecretName) ? [] : [
  {
    name: auth.entraClientAuth == 'certificate' ? 'ENTRA_CLIENT_CERTIFICATE' : 'ENTRA_CLIENT_SECRET'
    secretRef: 'entra-client-credential'
  }
])

resource api 'Microsoft.App/containerApps@2024-03-01' = {
  name: backendName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${backendIdentityId}': {}
    }
  }
  properties: {
    environmentId: env.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: false // internal only: reachable from the web app, not the internet
        targetPort: 8000
        transport: 'http'
        // Plain http inside the environment (web -> api); TLS terminates at the public ingress.
        allowInsecure: true
      }
      registries: [
        {
          server: registryLoginServer
          identity: backendIdentityId
        }
      ]
      secrets: [
        for s in items(kvSecret): {
          name: s.key
          keyVaultUrl: '${keyVaultUri}secrets/${s.value}'
          identity: backendIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'api'
          image: backendImage
          resources: {
            cpu: json(backendCpu)
            memory: backendMemory
          }
          env: concat([
            { name: 'APP_ENV', value: 'production' }
            { name: 'LOG_FORMAT', value: 'json' }
            { name: 'WEB_CONCURRENCY', value: string(backendWorkers) }
            { name: 'DATABASE_URL', secretRef: 'database-url' }
            { name: 'DB_AUTO_MIGRATE', value: 'true' }
            { name: 'SESSION_SECRET', secretRef: 'session-secret' }
            { name: 'COOKIE_SECURE', value: 'true' }
            { name: 'CORS_ORIGINS', value: frontendOrigin }
            { name: 'TRUST_PROXY_HEADERS', value: 'true' }
            { name: 'TRUSTED_PROXY_CIDRS', value: trustedProxyCidrs }
            { name: 'INGEST_API_TOKEN', secretRef: 'ingest-api-token' }
            { name: 'ADMIN_EMAIL', value: adminEmail }
            { name: 'ADMIN_PASSWORD', secretRef: 'admin-password' }
            { name: 'SIMULATION_MODE', value: string(simulationMode) }
            // Leader election makes this safe with several replicas.
            { name: 'SIMULATOR_ENABLED', value: 'true' }
            { name: 'AZURE_AUTH_MODE', value: 'managed_identity' }
            { name: 'AZURE_MANAGED_IDENTITY_CLIENT_ID', value: backendIdentityClientId }
            { name: 'AZURE_SUBSCRIPTION_IDS', value: scanSubscriptionIds }
            // Scheduled posture scans of every configured connector (leader-elected,
            // so one scheduler for all replicas). Admins can override in the console.
            { name: 'SCAN_SCHEDULE_ENABLED', value: 'true' }
            { name: 'SCAN_INTERVAL_HOURS', value: '6' }
            // Alert notifications (docs/NOTIFICATIONS.md). Outbound calls to Teams,
            // Slack, SMTP/ACS and webhooks leave through the environment's default
            // egress (no NAT gateway / firewall is deployed). If you add an Azure
            // Firewall or NSG egress rules, allow 443 to the webhook hosts and your
            // SMTP port. The dispatcher is leader-elected, so replicas never double-send.
            { name: 'PUBLIC_BASE_URL', value: notificationsBaseUrl }
            { name: 'NOTIFICATIONS_ENCRYPTION_KEY', secretRef: 'notifications-encryption-key' }
          ], authEnv)
          probes: [
            {
              type: 'Startup'
              httpGet: {
                path: '/api/health'
                port: 8000
              }
              initialDelaySeconds: 5
              periodSeconds: 5
              failureThreshold: 36 // first start runs migrations + seeding
            }
            {
              type: 'Liveness'
              httpGet: {
                path: '/api/health'
                port: 8000
              }
              periodSeconds: 30
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/api/health'
                port: 8000
              }
              periodSeconds: 10
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: backendMinReplicas
        maxReplicas: backendMaxReplicas
        rules: [
          {
            name: 'http'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

resource web 'Microsoft.App/containerApps@2024-03-01' = {
  name: frontendName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${frontendIdentityId}': {}
    }
  }
  properties: {
    environmentId: env.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false // http is redirected to https
      }
      registries: [
        {
          server: registryLoginServer
          identity: frontendIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'web'
          image: frontendImage
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            // Container Apps routes in-environment calls by app name.
            { name: 'BACKEND_URL', value: 'http://${api.name}' }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/healthz'
                port: 8080
              }
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/healthz'
                port: 8080
              }
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: frontendMinReplicas
        maxReplicas: frontendMaxReplicas
        rules: [
          {
            name: 'http'
            http: {
              metadata: {
                concurrentRequests: '100'
              }
            }
          }
        ]
      }
    }
  }
}

output environmentName string = env.name
output defaultDomain string = env.properties.defaultDomain
output backendAppName string = api.name
output frontendAppName string = web.name
output frontendFqdn string = web.properties.configuration.ingress.fqdn
output frontendUrl string = 'https://${web.properties.configuration.ingress.fqdn}'
output entraRedirectUri string = entraRedirectUri
