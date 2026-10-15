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
param publicBaseUrl = readEnvironmentVariable('CNAPP_PUBLIC_BASE_URL', '')

// Secrets (required, no defaults): generated on the first deployment and read
// back from Key Vault afterwards by the workflow (.github/workflows/deploy.yml).
param postgresAdminPassword = readEnvironmentVariable('CNAPP_POSTGRES_PASSWORD')
param ingestApiToken = readEnvironmentVariable('CNAPP_INGEST_API_TOKEN')
param adminPassword = readEnvironmentVariable('CNAPP_ADMIN_PASSWORD')
param sessionSecret = readEnvironmentVariable('CNAPP_SESSION_SECRET')
param notificationsEncryptionKey = readEnvironmentVariable('CNAPP_NOTIFICATIONS_ENCRYPTION_KEY')
