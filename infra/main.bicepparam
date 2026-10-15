// Parameters for main.bicep, read from environment variables so the deploy
// workflow never writes secrets to disk or to the command line.
//
//   az deployment group create -g <rg> -f infra/main.bicep -p infra/main.bicepparam
using 'main.bicep'

param location = readEnvironmentVariable('AZURE_LOCATION', 'eastus')
param namePrefix = readEnvironmentVariable('CNAPP_NAME_PREFIX', 'cnapp')
param deployApps = bool(readEnvironmentVariable('CNAPP_DEPLOY_APPS', 'true'))
param backendImage = readEnvironmentVariable('CNAPP_BACKEND_IMAGE', 'cnapp-backend:latest')
param frontendImage = readEnvironmentVariable('CNAPP_FRONTEND_IMAGE', 'cnapp-frontend:latest')
param adminEmail = readEnvironmentVariable('CNAPP_ADMIN_EMAIL', 'admin@example.com')
param simulationMode = bool(readEnvironmentVariable('CNAPP_SIMULATION_MODE', 'true'))
param scanSubscriptionIds = readEnvironmentVariable('CNAPP_SCAN_SUBSCRIPTION_IDS', '')
// MFA / Microsoft sign-in (repository variables; identifiers only, see docs/AUTH.md)
param mfaRequiredRoles = readEnvironmentVariable('CNAPP_MFA_REQUIRED_ROLES', '')
param passwordLoginEnabled = bool(readEnvironmentVariable('CNAPP_PASSWORD_LOGIN_ENABLED', 'true'))
param breakGlassEmails = readEnvironmentVariable('CNAPP_BREAK_GLASS_EMAILS', '')
param entraClientId = readEnvironmentVariable('CNAPP_ENTRA_CLIENT_ID', '')
param entraClientAuth = readEnvironmentVariable('CNAPP_ENTRA_CLIENT_AUTH', 'managed_identity')
param entraCredentialSecretName = readEnvironmentVariable('CNAPP_ENTRA_CREDENTIAL_SECRET_NAME', '')
param entraRoleMap = readEnvironmentVariable('CNAPP_ENTRA_ROLE_MAP', 'CNAPP.Admin=admin,CNAPP.Analyst=analyst,CNAPP.Viewer=viewer')
param entraJitProvisioning = bool(readEnvironmentVariable('CNAPP_ENTRA_JIT_PROVISIONING', 'false'))
param entraDefaultRole = readEnvironmentVariable('CNAPP_ENTRA_DEFAULT_ROLE', 'viewer')

// Secrets (required, no defaults): generated on the first deployment and read
// back from Key Vault afterwards by the workflow (.github/workflows/deploy.yml).
param postgresAdminPassword = readEnvironmentVariable('CNAPP_POSTGRES_PASSWORD')
param ingestApiToken = readEnvironmentVariable('CNAPP_INGEST_API_TOKEN')
param adminPassword = readEnvironmentVariable('CNAPP_ADMIN_PASSWORD')
param sessionSecret = readEnvironmentVariable('CNAPP_SESSION_SECRET')
param mfaEncryptionKey = readEnvironmentVariable('CNAPP_MFA_ENCRYPTION_KEY')
