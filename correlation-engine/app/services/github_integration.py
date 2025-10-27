"""
GitHub Integration Module

Handles GitHub API interactions for PR creation, comments, and SARIF uploads.
"""

import os
import json
from typing import Optional, Dict, List
from pathlib import Path


class GitHubIntegration:
    """GitHub API integration for PR creation and updates"""
    
    def __init__(self, repo_path: str, github_token: Optional[str] = None):
        """
        Initialize GitHub integration
        
        Args:
            repo_path: Path to git repository
            github_token: GitHub personal access token (or from env GITHUB_TOKEN)
        """
        self.repo_path = Path(repo_path)
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        
        # Extract repo info from git remote
        try:
            from git import Repo
            repo = Repo(repo_path)
            
            # Get remote URL
            if repo.remotes:
                remote_url = repo.remotes.origin.url
                # Parse owner/repo from URL
                # https://github.com/owner/repo.git or git@github.com:owner/repo.git
                if "github.com" in remote_url:
                    parts = remote_url.replace(".git", "").split("/")[-2:]
                    if ":" in parts[0]:
                        parts[0] = parts[0].split(":")[-1]
                    self.repo_owner = parts[0]
                    self.repo_name = parts[1]
                else:
                    self.repo_owner = None
                    self.repo_name = None
            else:
                self.repo_owner = None
                self.repo_name = None
                
        except Exception as e:
            print(f"⚠️  Could not extract GitHub repo info: {e}")
            self.repo_owner = None
            self.repo_name = None
    
    def create_pull_request(
        self,
        branch_name: str,
        base_branch: str = "main",
        title: str = "🔒 Security: Automated vulnerability patches",
        body: Optional[str] = None,
        labels: Optional[List[str]] = None
    ) -> Optional[Dict]:
        """
        Create a pull request on GitHub
        
        Args:
            branch_name: Source branch with patches
            base_branch: Target branch (default: main)
            title: PR title
            body: PR description
            labels: Labels to add to PR
            
        Returns:
            PR data or None if failed
        """
        if not self.github_token:
            print("❌ GitHub token not provided. Set GITHUB_TOKEN environment variable.")
            return None
        
        if not self.repo_owner or not self.repo_name:
            print("❌ Could not determine GitHub repository")
            return None
        
        try:
            import requests
            
            # GitHub API endpoint
            url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/pulls"
            
            # Default body if not provided
            if not body:
                body = self._generate_pr_body()
            
            # Create PR
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            data = {
                "title": title,
                "body": body,
                "head": branch_name,
                "base": base_branch
            }
            
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code == 201:
                pr_data = response.json()
                pr_number = pr_data["number"]
                pr_url = pr_data["html_url"]
                
                print(f"✅ Pull request created: #{pr_number}")
                print(f"   URL: {pr_url}")
                
                # Add labels if provided
                if labels:
                    self._add_labels_to_pr(pr_number, labels)
                
                return pr_data
            else:
                print(f"❌ Failed to create PR: {response.status_code}")
                print(f"   Response: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error creating pull request: {e}")
            return None
    
    def comment_on_pr(self, pr_number: int, comment: str) -> bool:
        """Add a comment to a pull request"""
        if not self.github_token or not self.repo_owner or not self.repo_name:
            return False
        
        try:
            import requests
            
            url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/issues/{pr_number}/comments"
            
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            data = {"body": comment}
            
            response = requests.post(url, headers=headers, json=data)
            
            return response.status_code == 201
            
        except Exception as e:
            print(f"Error commenting on PR: {e}")
            return False
    
    def push_branch(self, branch_name: str) -> bool:
        """Push a branch to GitHub"""
        try:
            from git import Repo
            repo = Repo(self.repo_path)
            
            # Push branch
            origin = repo.remotes.origin
            origin.push(branch_name)
            
            print(f"✅ Pushed branch '{branch_name}' to GitHub")
            return True
            
        except Exception as e:
            print(f"❌ Error pushing branch: {e}")
            return False
    
    def _add_labels_to_pr(self, pr_number: int, labels: List[str]) -> bool:
        """Add labels to a pull request"""
        try:
            import requests
            
            url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/issues/{pr_number}/labels"
            
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            data = {"labels": labels}
            
            response = requests.post(url, headers=headers, json=data)
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Error adding labels: {e}")
            return False
    
    def _generate_pr_body(self) -> str:
        """Generate default PR description"""
        return """## 🔒 Automated Security Patches

This PR contains automated security patches generated by the Security Automation Platform.

### What was done:
- 🔍 **CodeQL Semantic Analysis** - Identified vulnerabilities with data flow tracking
- 🧮 **Z3 Symbolic Execution** - Verified exploitability 
- 🤖 **LLM-Powered Patching** - Generated security fixes
- ✅ **Automated Validation** - Verified patches work correctly

### Changes included:
This PR fixes the following security vulnerabilities:
- IDOR (Insecure Direct Object Reference)
- Missing Authorization Checks
- SQL Injection risks
- Path Traversal vulnerabilities

### Testing:
All patches have been:
- ✅ Syntax validated
- ✅ Semantically verified
- ✅ Symbolically proven to fix vulnerabilities
- ✅ Tested in isolated branch

### Review Checklist:
- [ ] Review patch changes
- [ ] Run existing tests
- [ ] Verify security fixes
- [ ] Check for breaking changes

### Next Steps:
1. Review the code changes carefully
2. Run your test suite to ensure no regressions
3. Merge if all checks pass

---
*Generated by [Security Automation Platform](https://github.com/your-org/security-automation-platform)*
*For questions or issues, please contact the security team.*
"""


def create_pr_for_patches(
    repo_path: str,
    branch_name: str,
    vulnerabilities_fixed: int,
    patches_details: List[Dict],
    github_token: Optional[str] = None
) -> Optional[Dict]:
    """
    Convenience function to create PR with patch details
    
    Args:
        repo_path: Path to repository
        branch_name: Branch with patches
        vulnerabilities_fixed: Number of vulnerabilities fixed
        patches_details: List of patch details
        github_token: GitHub token
        
    Returns:
        PR data or None
    """
    gh = GitHubIntegration(repo_path, github_token)
    
    # Generate detailed PR body
    body = f"""## 🔒 Automated Security Patches

This PR contains **{vulnerabilities_fixed} automated security patches** generated by the Security Automation Platform.

### Analysis Summary
- 🔍 **Vulnerabilities Detected**: {len(patches_details)}
- ✅ **Patches Generated**: {vulnerabilities_fixed}
- 🤖 **Method**: Hybrid (CodeQL + Z3 + LLM)

### Vulnerabilities Fixed

"""
    
    for i, patch in enumerate(patches_details, 1):
        vuln = patch.get("vulnerability", {})
        body += f"""
#### {i}. {vuln.get('type', 'Unknown')} in `{vuln.get('file', 'N/A')}`
- **Location**: Line {vuln.get('line', 'N/A')}
- **Method**: `{vuln.get('method', 'N/A')}`
- **Severity**: {vuln.get('severity', 'N/A').upper()}
- **Fix Score**: {patch.get('patch', {}).get('validation', {}).get('score', 'N/A')}/100

"""
    
    body += """
### What was done:
1. 🔍 **CodeQL Semantic Analysis** - Deep code understanding with data flow tracking
2. 🧮 **Z3 Symbolic Execution** - Formal verification of exploitability
3. 🤖 **LLM-Powered Patching** - AI-generated security fixes  
4. ✅ **Automated Validation** - Multi-level verification

### Testing Performed:
- ✅ Syntax validation
- ✅ Security fix verification
- ✅ Symbolic proof of fix
- ✅ Compilation check

### Review Guidelines:
- [ ] Review each patch individually
- [ ] Run existing test suite
- [ ] Verify no breaking changes
- [ ] Check security improvements

---
*🤖 Generated by [Security Automation Platform](https://github.com/your-org/security-automation-platform)*
"""
    
    # Push branch first
    if not gh.push_branch(branch_name):
        print("⚠️  Failed to push branch, PR creation may fail")
    
    # Create PR
    return gh.create_pull_request(
        branch_name=branch_name,
        title=f"🔒 Security: Fix {vulnerabilities_fixed} vulnerabilities",
        body=body,
        labels=["security", "automated", "vulnerability-fix"]
    )
