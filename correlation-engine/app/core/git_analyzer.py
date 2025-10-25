"""
Git History Analyzer for Phase 2
Tracks code changes and identifies when vulnerabilities were introduced
"""

from typing import List, Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path
import hashlib

try:
    from git import Repo, Commit
    from git.exc import InvalidGitRepositoryError, GitCommandError
except ImportError:
    print("⚠️  GitPython not installed. Run: pip install gitpython")
    Repo = None


class GitHistoryAnalyzer:
    """Analyzes Git repository history for security-relevant changes"""
    
    def __init__(self, repo_path: str):
        """
        Initialize analyzer with repository path.
        
        Args:
            repo_path: Path to git repository root
        """
        if Repo is None:
            raise ImportError("GitPython is required for git analysis")
        
        try:
            self.repo = Repo(repo_path)
            self.repo_path = Path(repo_path)
        except InvalidGitRepositoryError:
            raise ValueError(f"Not a git repository: {repo_path}")
    
    def get_current_commit(self) -> Dict[str, any]:
        """Get current commit information"""
        commit = self.repo.head.commit
        return self._commit_to_dict(commit)
    
    def get_commit_history(self, max_count: int = 50) -> List[Dict[str, any]]:
        """
        Get recent commit history.
        
        Args:
            max_count: Maximum number of commits to retrieve
            
        Returns:
            List of commit dictionaries
        """
        commits = []
        for commit in self.repo.iter_commits(max_count=max_count):
            commits.append(self._commit_to_dict(commit))
        return commits
    
    def get_file_history(self, file_path: str, max_count: int = 20) -> List[Dict[str, any]]:
        """
        Get commit history for a specific file.
        
        Args:
            file_path: Relative path to file from repo root
            max_count: Maximum commits to retrieve
            
        Returns:
            List of commits that modified the file
        """
        commits = []
        try:
            for commit in self.repo.iter_commits(paths=file_path, max_count=max_count):
                commit_dict = self._commit_to_dict(commit)
                commit_dict['file_path'] = file_path
                commits.append(commit_dict)
        except GitCommandError:
            pass  # File might not exist or no commits
        
        return commits
    
    def find_when_line_introduced(self, file_path: str, line_number: int) -> Optional[Dict[str, any]]:
        """
        Find which commit introduced a specific line.
        Uses git blame to trace line origins.
        
        Args:
            file_path: File path relative to repo root
            line_number: Line number (1-indexed)
            
        Returns:
            Commit information or None if not found
        """
        try:
            # Git blame returns commits for each line
            blame_data = self.repo.blame('HEAD', file_path)
            
            current_line = 1
            for commit, lines in blame_data:
                num_lines = len(lines)
                if current_line <= line_number < current_line + num_lines:
                    return self._commit_to_dict(commit)
                current_line += num_lines
                
        except (GitCommandError, FileNotFoundError):
            pass
        
        return None
    
    def get_file_changes_between_commits(
        self,
        from_commit: str,
        to_commit: str = "HEAD"
    ) -> List[Dict[str, any]]:
        """
        Get files changed between two commits.
        
        Args:
            from_commit: Starting commit hash or reference
            to_commit: Ending commit hash or reference (default: HEAD)
            
        Returns:
            List of changed files with change type and stats
        """
        try:
            from_commit_obj = self.repo.commit(from_commit)
            to_commit_obj = self.repo.commit(to_commit)
            
            diffs = from_commit_obj.diff(to_commit_obj)
            
            changes = []
            for diff in diffs:
                change = {
                    'file_path': diff.b_path or diff.a_path,
                    'change_type': self._get_change_type(diff),
                    'lines_added': diff.b_blob.size if diff.b_blob else 0,
                    'lines_deleted': diff.a_blob.size if diff.a_blob else 0,
                }
                changes.append(change)
            
            return changes
            
        except (GitCommandError, ValueError):
            return []
    
    def analyze_commit_for_security_keywords(self, commit_hash: str) -> Dict[str, any]:
        """
        Analyze commit message and changes for security-related keywords.
        
        Args:
            commit_hash: Commit to analyze
            
        Returns:
            Analysis results with security indicators
        """
        commit = self.repo.commit(commit_hash)
        message = commit.message.lower()
        
        # Security keywords to look for
        fix_keywords = ['fix', 'patch', 'resolve', 'security', 'vulnerability', 'cve']
        intro_keywords = ['add', 'implement', 'new', 'create']
        
        analysis = {
            'commit_hash': commit_hash,
            'is_security_fix': any(keyword in message for keyword in fix_keywords),
            'is_new_feature': any(keyword in message for keyword in intro_keywords),
            'message': commit.message,
            'files_changed': len(commit.stats.files),
            'lines_changed': commit.stats.total['lines'],
        }
        
        return analysis
    
    def get_blame_info(self, file_path: str, line_number: int) -> Optional[Dict[str, any]]:
        """
        Get detailed blame information for a specific line.
        
        Args:
            file_path: File path relative to repo root
            line_number: Line number (1-indexed)
            
        Returns:
            Blame information including commit, author, date
        """
        introduced_commit = self.find_when_line_introduced(file_path, line_number)
        
        if introduced_commit:
            return {
                'file_path': file_path,
                'line_number': line_number,
                'commit_hash': introduced_commit['hash'],
                'author': introduced_commit['author'],
                'date': introduced_commit['date'],
                'message': introduced_commit['message'],
            }
        
        return None
    
    def calculate_file_churn(self, file_path: str, since_commit: Optional[str] = None) -> Dict[str, int]:
        """
        Calculate code churn for a file (how much it changes).
        
        Args:
            file_path: File to analyze
            since_commit: Count changes since this commit (None = all history)
            
        Returns:
            Churn metrics (commits, additions, deletions)
        """
        commits = self.get_file_history(file_path, max_count=100)
        
        if since_commit:
            # Filter commits after the specified one
            found = False
            filtered = []
            for commit in commits:
                if commit['hash'] == since_commit:
                    found = True
                if found:
                    filtered.append(commit)
            commits = filtered
        
        return {
            'file_path': file_path,
            'total_commits': len(commits),
            'first_commit': commits[-1] if commits else None,
            'last_commit': commits[0] if commits else None,
        }
    
    def _commit_to_dict(self, commit: 'Commit') -> Dict[str, any]:
        """Convert Git commit object to dictionary"""
        return {
            'hash': commit.hexsha,
            'short_hash': commit.hexsha[:8],
            'author': str(commit.author),
            'author_email': commit.author.email,
            'date': datetime.fromtimestamp(commit.committed_date),
            'message': commit.message.strip(),
            'summary': commit.summary,
        }
    
    def _get_change_type(self, diff) -> str:
        """Determine type of change from diff object"""
        if diff.new_file:
            return "added"
        elif diff.deleted_file:
            return "deleted"
        elif diff.renamed_file:
            return "renamed"
        else:
            return "modified"
    
    @staticmethod
    def generate_vulnerability_fingerprint(
        file_path: str,
        line_number: int,
        vuln_type: str
    ) -> str:
        """
        Generate unique fingerprint for vulnerability tracking.
        Uses file path, line number, and type to create stable ID.
        
        Args:
            file_path: File containing vulnerability
            line_number: Line number
            vuln_type: Type of vulnerability
            
        Returns:
            64-character hex fingerprint
        """
        # Normalize path (use forward slashes)
        normalized_path = file_path.replace('\\', '/')
        
        # Create fingerprint string
        fingerprint_str = f"{normalized_path}:{line_number}:{vuln_type}"
        
        # Hash it
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
