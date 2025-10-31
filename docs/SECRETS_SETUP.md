# Secrets Configuration Guide

This guide explains how to configure the required secrets for the DevSecOps Security Scanner project.

## Required Secrets

The project uses several optional secrets to enable advanced features:

1. **SONAR_TOKEN** - SonarQube authentication token (optional)
2. **SONAR_HOST_URL** - SonarQube server URL (optional, defaults to https://sonarcloud.io)
3. **SNYK_TOKEN** - Snyk API token (optional)
4. **OPENAI_API_KEY** - OpenAI API key for LLM policy generation (optional)
5. **HF_TOKEN** - Hugging Face API token for LLM policy generation (optional)

---

## Local Development Setup

### 1. Create `.env` File

Copy the example file:

```bash
cp env.example.txt .env
```

### 2. Add Your Secrets

Edit `.env` and add your actual secret values:

```bash
# SonarQube (Optional)
SONAR_TOKEN=your-actual-sonar-token
SONAR_HOST_URL=https://sonarcloud.io

# Snyk (Optional)
SNYK_TOKEN=your-actual-snyk-token

# LLM APIs (Optional)
OPENAI_API_KEY=sk-your-actual-openai-key
HF_TOKEN=your-actual-hf-token
```

### 3. Verify Setup

The `.env` file is automatically loaded by Python scripts using `python-dotenv`. You can test it:

```bash
python -c "from dotenv import load_dotenv; import os; load_dotenv(); print('OPENAI_API_KEY:', 'SET' if os.getenv('OPENAI_API_KEY') else 'NOT SET')"
```

---

## GitHub Secrets Setup (CI/CD)

### For GitHub Actions Workflows

To enable optional features in GitHub Actions workflows, add secrets to your repository:

#### Step 1: Navigate to Repository Settings

1. Go to your GitHub repository
2. Click **Settings** (top navigation)
3. Click **Secrets and variables** → **Actions** (left sidebar)

#### Step 2: Add New Secrets

Click **New repository secret** and add each secret:

| Secret Name | Description | Required | Where to Get |
|------------|------------|----------|--------------|
| `SONAR_TOKEN` | SonarQube authentication token | No | [SonarCloud](https://sonarcloud.io/) → My Account → Security |
| `SONAR_HOST_URL` | SonarQube server URL | No | Default: `https://sonarcloud.io` or your self-hosted URL |
| `SNYK_TOKEN` | Snyk API token | No | [Snyk Dashboard](https://app.snyk.io/) → Settings → Account → Auth Token |
| `OPENAI_API_KEY` | OpenAI API key | No | [OpenAI Platform](https://platform.openai.com/api-keys) |
| `HF_TOKEN` | Hugging Face API token | No | [Hugging Face Settings](https://huggingface.co/settings/tokens) |

#### Step 3: Verify Secrets Are Set

After adding secrets, they will be available in your GitHub Actions workflows:

- ✅ Workflows will automatically use these secrets when available
- ⚠️ Workflows will skip optional steps if secrets are not set
- 📝 Check workflow logs to see which steps ran or were skipped

---

## How Secrets Are Used

### In GitHub Actions Workflows

Secrets are referenced using `${{ secrets.SECRET_NAME }}`:

```yaml
env:
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  HF_TOKEN: ${{ secrets.HF_TOKEN }}
```

### In Local Python Scripts

Secrets are loaded from `.env` file:

```python
from dotenv import load_dotenv
import os

load_dotenv()  # Loads .env file automatically
api_key = os.getenv("OPENAI_API_KEY")
```

---

## Feature Enablement Matrix

| Feature | Secret Required | Workflow |
|---------|----------------|----------|
| SonarQube SAST Scan | `SONAR_TOKEN` | `sast.yml` |
| Snyk SCA Scan | `SNYK_TOKEN` | `sca.yml` |
| OpenAI Policy Generation | `OPENAI_API_KEY` | `sast.yml`, `sca.yml`, `dast.yml` |
| Hugging Face Policy Generation | `HF_TOKEN` | `sast.yml`, `sca.yml`, `dast.yml` |

---

## Security Best Practices

✅ **DO:**
- Use `.env.example` as a template (never commit actual secrets)
- Add `.env` to `.gitignore` (already configured)
- Use GitHub Secrets for CI/CD workflows
- Rotate secrets regularly
- Use least-privilege tokens (only grant necessary permissions)

❌ **DON'T:**
- Commit `.env` files to git
- Share secrets in chat/messages
- Use production secrets in development
- Hardcode secrets in code
- Log secret values

---

## Troubleshooting

### Secret Not Working in GitHub Actions

1. **Check secret name**: Ensure it matches exactly (case-sensitive)
2. **Check permissions**: Verify the workflow has access to secrets
3. **Check workflow syntax**: Verify `${{ secrets.SECRET_NAME }}` is correct
4. **Check logs**: Look for "skipped" or "not set" messages in workflow logs

### Secret Not Loading Locally

1. **Verify `.env` file exists**: `ls -la .env`
2. **Check file location**: `.env` should be in project root
3. **Verify `python-dotenv` installed**: `pip install python-dotenv`
4. **Check syntax**: Ensure no spaces around `=` in `.env` file

### Example `.env` Format

```bash
# ✅ Correct
OPENAI_API_KEY=sk-proj-abc123...
HF_TOKEN=hf_xyz789...

# ❌ Incorrect (spaces around =)
OPENAI_API_KEY = sk-proj-abc123...
HF_TOKEN =hf_xyz789...
```

---

## Getting API Keys

### OpenAI API Key

1. Go to https://platform.openai.com/
2. Sign up or log in
3. Navigate to **API keys**
4. Click **Create new secret key**
5. Copy and save immediately (won't be shown again)

### Hugging Face Token

1. Go to https://huggingface.co/
2. Sign up or log in
3. Go to **Settings** → **Access Tokens**
4. Click **New token**
5. Select permissions (read/write as needed)
6. Copy the token

### Snyk Token

1. Go to https://app.snyk.io/
2. Sign up or log in
3. Go to **Settings** → **Account** → **Auth Token**
4. Copy the token or generate a new one

### SonarQube Token

**For SonarCloud:**
1. Go to https://sonarcloud.io/
2. Sign up or log in
3. Go to **My Account** → **Security**
4. Generate a new token

**For Self-Hosted:**
1. Log in to your SonarQube instance
2. Go to **My Account** → **Security**
3. Generate a new token
4. Set `SONAR_HOST_URL` to your server URL

---

## Next Steps

After setting up secrets:

1. ✅ Test locally with `.env` file
2. ✅ Add secrets to GitHub repository settings
3. ✅ Trigger a workflow to verify secrets work
4. ✅ Check workflow logs for successful steps

For more information, see:
- [GitHub Actions Secrets Documentation](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [Project README](README.md)
- [Quick Start Guide](QUICKSTART.md)

