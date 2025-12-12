# Secrets Management Guide

## Overview
This document outlines how to securely manage secrets (passwords, API keys, tokens) in the UniClub application.

## Current Secrets

### Required Secrets
1. **SESSION_SECRET** - Used for session encryption
2. **Database Credentials** - Database username, password, host
3. **Email Service Credentials** - SMTP credentials (if using email)
4. **API Keys** - External service API keys (if any)

## Secret Storage

### Development
- Store secrets in `.env` file (never commit to git)
- Use `.env.example` as a template
- Add `.env` to `.gitignore`

### Production
**DO NOT** store secrets in:
- ❌ Code files
- ❌ Environment files committed to git
- ❌ Configuration files in repository
- ❌ Hardcoded in source code

**DO** use:
- ✅ Secret management service (AWS Secrets Manager, HashiCorp Vault, etc.)
- ✅ Environment variables set by deployment system
- ✅ Encrypted configuration files
- ✅ Cloud provider secret stores

## Secret Rotation Policy

### SESSION_SECRET
- **Rotation Frequency:** Every 90 days
- **Impact:** All user sessions will be invalidated
- **Procedure:**
  1. Generate new secret
  2. Update secret in secret manager
  3. Restart application
  4. Users will need to log in again

### Database Credentials
- **Rotation Frequency:** Every 180 days
- **Impact:** Brief downtime during rotation
- **Procedure:**
  1. Create new database user with same permissions
  2. Update application configuration
  3. Test connection with new credentials
  4. Update secret in secret manager
  5. Restart application
  6. Remove old database user after verification

### API Keys
- **Rotation Frequency:** As needed (when compromised or expired)
- **Impact:** Service-specific
- **Procedure:**
  1. Generate new API key from service provider
  2. Update secret in secret manager
  3. Restart application
  4. Revoke old API key

## Secret Generation

### SESSION_SECRET
```bash
# Generate a secure random secret (64 characters)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Database Password
```bash
# Generate a secure password (32 characters)
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
```

## Secret Manager Integration

### AWS Secrets Manager
```javascript
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

const client = new SecretsManagerClient({ region: "us-east-1" });

async function getSecret(secretName) {
  const command = new GetSecretValueCommand({ SecretId: secretName });
  const response = await client.send(command);
  return JSON.parse(response.SecretString);
}
```

### HashiCorp Vault
```javascript
import vault from 'node-vault';

const vaultClient = vault({
  endpoint: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN
});

async function getSecret(path) {
  const secret = await vaultClient.read(path);
  return secret.data;
}
```

## Environment Variables Template

Create a `.env.example` file (committed to git):
```env
# Session
SESSION_SECRET=change-me-in-production

# Database
DATABASE_URL=mysql://user:password@host:port/database
# OR
MAIN_DB_HOST=localhost
MAIN_DB_USER=root
MAIN_DB_PASSWORD=
MAIN_DB_NAME=Uniclub
MAIN_DB_PORT=3306

# Email (if using)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user@example.com
SMTP_PASSWORD=password

# Application
NODE_ENV=production
PORT=3000
ALLOWED_ORIGINS=https://yourdomain.com

# Logging
LOG_LEVEL=info
LOG_DIR=./logs

# Security
CSRF_DISABLED=false
```

## Security Best Practices

1. **Never commit secrets to git**
   - Use `.gitignore` to exclude `.env`
   - Review commits before pushing
   - Use pre-commit hooks to scan for secrets

2. **Use strong secrets**
   - Minimum 32 characters for SESSION_SECRET
   - Use cryptographically secure random generators
   - Avoid dictionary words or patterns

3. **Limit secret access**
   - Only grant access to necessary personnel
   - Use role-based access in secret manager
   - Audit secret access logs

4. **Rotate regularly**
   - Follow rotation schedule
   - Document rotation procedures
   - Test rotation process in staging

5. **Monitor secret usage**
   - Alert on unusual access patterns
   - Log all secret access
   - Review access logs regularly

## Incident Response

### If Secret is Compromised
1. **Immediately rotate the secret**
2. **Revoke old secret**
3. **Investigate how it was compromised**
4. **Review access logs**
5. **Notify affected users if necessary**
6. **Update security procedures**

### If Secret is Exposed in Code
1. **Remove secret from code immediately**
2. **Rotate the secret**
3. **Review git history and remove from all commits**
4. **Force push to remove from remote (if safe)**
5. **Notify team members**

## Checklist

### Pre-Production
- [ ] All secrets moved to secret manager
- [ ] `.env` file removed from repository
- [ ] `.env.example` created and committed
- [ ] `.gitignore` includes `.env`
- [ ] Secret rotation procedures documented
- [ ] Secret access controls configured
- [ ] Backup secrets stored securely

### Production
- [ ] Secrets loaded from secret manager
- [ ] No hardcoded secrets in code
- [ ] Secret rotation schedule established
- [ ] Access logs enabled
- [ ] Monitoring configured for secret access
- [ ] Incident response plan documented

## Tools

### Secret Scanning
- **git-secrets** - Prevents committing secrets
- **truffleHog** - Scans git history for secrets
- **gitleaks** - Detects secrets in git repos

### Secret Management
- **AWS Secrets Manager** - Cloud-based secret management
- **HashiCorp Vault** - Self-hosted secret management
- **Azure Key Vault** - Microsoft cloud secret management
- **Google Secret Manager** - Google cloud secret management

## References
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [NIST Secret Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

