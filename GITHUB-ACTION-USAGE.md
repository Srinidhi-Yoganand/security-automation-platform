# 🔌 Add to Any Project - GitHub Action Guide

## 1-Minute Setup for YOUR Repository

### Step 1: Add Workflow File

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on: [pull_request, push]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: Srinidhi-Yoganand/security-automation-platform@main
        with:
          language: 'java'  # Change to your language
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

### Step 2: Push & Done! 🎉

That's it! Now your repo will:
- ✅ Scan code on every PR
- ✅ Find vulnerabilities  
- ✅ Generate patches
- ✅ Create PR with fixes
- ✅ Comment on PRs

---

## What You Get

### Automatic Security Scanning

Every time you create a PR or push code:

1. **CodeQL Analysis** - Finds vulnerabilities
2. **Z3 Verification** - Proves they're exploitable
3. **LLM Patching** - Generates fixes
4. **Validation** - Tests the patches
5. **Auto-PR** - Creates pull request with fixes

### Example PR Comment

```markdown
🔒 Security Analysis Report

Summary:
- Vulnerabilities Found: 5
- Vulnerabilities Fixed: 5

Patches submitted in PR #123
```

### Example Auto-Generated PR

```
🔒 Security: Fix 5 vulnerabilities

Automated patches for:
1. IDOR in UserController.java:26 ✅
2. Missing Auth in OrderService.java:54 ✅  
3. SQL Injection in ReportDAO.java:89 ✅

All patches validated and tested!
```

---

## Configuration Options

```yaml
- uses: Srinidhi-Yoganand/security-automation-platform@main
  with:
    # Required
    github_token: ${{ secrets.GITHUB_TOKEN }}
    
    # Optional
    target_path: '.'                  # Path to scan (default: .)
    language: 'java'                  # java, python, js, go
    generate_patches: true            # Auto-generate fixes
    create_pr: true                   # Auto-create PR
    llm_provider: 'template'          # template, gemini, openai
    fail_on_vulnerabilities: true     # Fail build if found
    upload_sarif: true                # Upload to GitHub Security
    
    # LLM Keys (optional, for better patches)
    gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

---

## Examples

### Java Spring Boot

```yaml
- uses: Srinidhi-Yoganand/security-automation-platform@main
  with:
    target_path: 'src/main/java'
    language: 'java'
    github_token: ${{ secrets.GITHUB_TOKEN }}
```

### Python Django

```yaml
- uses: Srinidhi-Yoganand/security-automation-platform@main
  with:
    language: 'python'
    llm_provider: 'gemini'
    gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
    github_token: ${{ secrets.GITHUB_TOKEN }}
```

### Monorepo (Multiple Projects)

```yaml
strategy:
  matrix:
    project:
      - { path: 'backend', lang: 'java' }
      - { path: 'frontend', lang: 'javascript' }
      - { path: 'api', lang: 'python' }

steps:
  - uses: Srinidhi-Yoganand/security-automation-platform@main
    with:
      target_path: ${{ matrix.project.path }}
      language: ${{ matrix.project.lang }}
      github_token: ${{ secrets.GITHUB_TOKEN }}
```

---

## Outputs

Use action outputs in subsequent steps:

```yaml
- id: security
  uses: Srinidhi-Yoganand/security-automation-platform@main
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}

- name: Post to Slack
  run: |
    echo "Found: ${{ steps.security.outputs.vulnerabilities_found }}"
    echo "Fixed: ${{ steps.security.outputs.vulnerabilities_fixed }}"
    echo "PR: ${{ steps.security.outputs.pr_url }}"
```

Available outputs:
- `vulnerabilities_found` - Number detected
- `vulnerabilities_fixed` - Number patched
- `pr_url` - Pull request URL
- `pr_number` - Pull request number

---

## FAQ

**Q: Does it work with private repos?**  
A: Yes! Use the built-in `GITHUB_TOKEN`.

**Q: Will it spam PRs?**  
A: No, only creates PR if vulnerabilities found.

**Q: Can I review patches before merging?**  
A: Yes! The PR is for review, not auto-merged.

**Q: What if I want to customize patches?**  
A: Review the PR, make changes, then merge.

**Q: Does it cost money?**  
A: Free! (Optional: LLM API keys for better patches)

---

## Full Documentation

- [Complete Guide](./docs/guides/END-TO-END-INTEGRATION.md)
- [Action Reference](./action.yml)
- [Examples](./docs/examples/)

---

**Add to your repo now and get automatic security fixes!** 🚀
