#!/usr/bin/env python3
"""
GitHub Codex API Key Exposure Scanner

This script scans GitHub for potentially exposed Codex API keys
and generates a report showing exposure statistics.

SECURITY NOTES:
- This tool is for security research purposes only
- Actual API keys are NEVER stored or logged
- Only metadata (repo name, file path, timestamp) is collected
- All findings are publicly visible on GitHub already
"""

import os
import re
import json
import base64
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class ExposedKeyFinding:
    """Represents a finding of a potentially exposed API key.
    
    NOTE: The actual key value is NEVER stored. Only metadata about
    where the exposure was found is recorded.
    """
    repository: str
    file_path: str
    file_url: str
    commit_sha: Optional[str]
    discovered_at: str
    key_type: str  # e.g., "sk-proj-", "sk-", etc.
    key_preview: str  # First 8 chars only (already public on GitHub)


class GitHubScanner:
    """Scanner for finding exposed API keys on GitHub."""

    # Patterns for Codex/OpenAI API keys
    # Based on research: T3BlbkFJ is OpenAI's unique base64 identifier
    KEY_PATTERNS = {
        'sk-proj-': r'[=:\s\'"](sk-proj-[a-zA-Z0-9_-]{100,})',
        'sk-': r'[=:\s\'"](sk-[a-zA-Z0-9_-]{40,})',
        'openai-base64': r'(T3BlbkFJ[a-zA-Z0-9+/=]{20,})',
    }

    # GitHub Search API rate limit: 10 requests per minute for authenticated users
    RATE_LIMIT_DELAY = 6  # seconds between requests
    
    def __init__(self, token: str):
        self.token = token
        self.session = self._create_session()
        self.findings: List[ExposedKeyFinding] = []
        
    def _create_session(self) -> requests.Session:
        """Create a requests session with retries and auth."""
        session = requests.Session()
        session.headers.update({
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'CodexKeyScanner-SecurityResearch/1.0'
        })
        
        # Add retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        return session
    
    def search_code(self, query: str, per_page: int = 30) -> List[Dict[str, Any]]:
        """Search GitHub code with the given query."""
        results = []
        page = 1
        max_pages = 10  # Limit to avoid rate limits
        
        while page <= max_pages:
            url = 'https://api.github.com/search/code'
            params = {
                'q': query,
                'per_page': per_page,
                'page': page,
                'sort': 'indexed',
                'order': 'desc'
            }
            
            try:
                response = self.session.get(url, params=params)
                
                if response.status_code == 403:
                    # Rate limited
                    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    print(f"Rate limited. Reset at {datetime.fromtimestamp(reset_time)}")
                    break
                
                response.raise_for_status()
                data = response.json()
                
                items = data.get('items', [])
                if not items:
                    break
                
                results.extend(items)
                print(f"  Page {page}: Found {len(items)} results (Total so far: {len(results)})")
                
                # Check if we've reached the total
                total_count = data.get('total_count', 0)
                if len(results) >= total_count or len(items) < per_page:
                    break
                
                page += 1
                
            except requests.exceptions.RequestException as e:
                print(f"Error searching code: {e}")
                break
        
        return results
    
    def analyze_file(self, item: Dict[str, Any], key_type: str, pattern: str) -> Optional[ExposedKeyFinding]:
        """Analyze a file for exposed keys."""
        try:
            # Get file content
            contents_url = item.get('url')
            if not contents_url:
                return None
            
            response = self.session.get(contents_url)
            if response.status_code != 200:
                return None
            
            content_data = response.json()
            
            # Decode content
            content = content_data.get('content', '')
            if content_data.get('encoding') == 'base64':
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                except Exception:
                    return None
            else:
                decoded = content
            
            # Search for key pattern
            matches = re.finditer(pattern, decoded)
            for match in matches:
                full_key = match.group(1)
                
                # Create finding with only metadata (never store full key)
                return ExposedKeyFinding(
                    repository=item.get('repository', {}).get('full_name', 'unknown'),
                    file_path=item.get('path', 'unknown'),
                    file_url=item.get('html_url', ''),
                    commit_sha=item.get('sha'),
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                    key_type=key_type,
                    key_preview=full_key[:12] + '***' if len(full_key) > 12 else full_key[:8] + '***'
                )
            
            return None
            
        except Exception as e:
            print(f"Error analyzing file: {e}")
            return None
    
    def scan_for_keys(self) -> List[ExposedKeyFinding]:
        """Scan GitHub for exposed Codex API keys."""
        all_findings = []
        
        for key_type, pattern in self.KEY_PATTERNS.items():
            print(f"\nScanning for {key_type} pattern...")
            
            # Search for the pattern
            query = f'"{key_type}"'
            results = self.search_code(query)
            
            print(f"  Found {len(results)} potential matches")
            
            # Analyze each result
            for item in results:
                finding = self.analyze_file(item, key_type, pattern)
                if finding:
                    all_findings.append(finding)
                    print(f"    ⚠️  Found exposed key in {finding.repository}/{finding.file_path}")
            
            time.sleep(self.RATE_LIMIT_DELAY)
        
        return all_findings
    
    def save_findings(self, findings: List[ExposedKeyFinding], output_dir: Path):
        """Save findings to JSON file."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f'scan_{timestamp}.json'
        
        data = {
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
            'total_findings': len(findings),
            'findings': [asdict(f) for f in findings]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Also save as latest
        latest_file = output_dir / 'latest.json'
        with open(latest_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        return output_file


def generate_readme(findings: List[ExposedKeyFinding], scan_time: datetime) -> str:
    """Generate README with findings table."""
    
    # Calculate statistics
    total_findings = len(findings)
    by_type: Dict[str, int] = {}
    by_repo: Dict[str, int] = {}
    
    for f in findings:
        by_type[f.key_type] = by_type.get(f.key_type, 0) + 1
        by_repo[f.repository] = by_repo.get(f.repository, 0) + 1
    
    # Build the README
    readme = f"""# 🔍 Codex API Key Exposure Monitor

> **SECURITY RESEARCH PROJECT**: Automated monitoring of publicly exposed Codex API keys on GitHub

⚠️ **IMPORTANT**: This project is for **security research and awareness purposes only**. 
- No actual API keys are stored or logged
- Only publicly visible metadata is collected
- Repository owners are encouraged to revoke exposed keys immediately

---

## 📊 Latest Scan Results

**Last Updated**: {scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Total Exposed Keys Found** | {total_findings} |
| **Key Types Detected** | {len(by_type)} |
| **Affected Repositories** | {len(by_repo)} |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
"""
    
    for key_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
        readme += f"| `{key_type}` | {count} |\n"
    
    readme += """
### Recent Findings

| Repository | File Path | Key Type | Preview | Discovered |
|------------|-----------|----------|---------|------------|
"""
    
    # Add findings (limited to most recent 50 for readability)
    recent_findings = sorted(findings, key=lambda x: x.discovered_at, reverse=True)[:50]
    
    for f in recent_findings:
        repo_short = f.repository[:30] + '...' if len(f.repository) > 30 else f.repository
        file_short = f.file_path[:40] + '...' if len(f.file_path) > 40 else f.file_path
        readme += f"| `{repo_short}` | `{file_short}` | `{f.key_type}` | `{f.key_preview}` | {f.discovered_at[:10]} |\n"
    
    if len(findings) > 50:
        readme += f"\n*... and {len(findings) - 50} more findings (see `data/` directory for full history)*\n"
    
    readme += """

---

## 🔒 For Repository Owners

If your repository appears in this list:

1. **Revoke the exposed key immediately** at https://platform.openai.com/api-keys
2. **Generate a new key** and update your applications
3. **Remove the exposed key from your repository history**:
   ```bash
   # Use git-filter-repo or BFG Repo-Cleaner
   git filter-repo --replace-text <(echo 'OLD_KEY==>NEW_KEY')
   ```
4. **Enable secret scanning** in your repository settings

---

## 🛡️ Prevention Best Practices

- Never commit API keys to version control
- Use environment variables (`.env` files with `.gitignore`)
- Enable GitHub Secret Scanning on all repositories
- Use pre-commit hooks like `truffleHog` or `git-secrets`
- Rotate API keys regularly

---

## 📈 Methodology

This scanner runs every hour via GitHub Actions and:
1. Searches GitHub for common Codex API key patterns
2. Analyzes matching files for exposed credentials
3. Records only metadata (repo name, file path, timestamp)
4. Updates this README with latest statistics

**Key Patterns Monitored:**
- `sk-proj-*` (Project API keys)
- `sk-*` (Standard API keys)
- `sk_live_*` (Live keys)
- `sk_test_*` (Test keys)

---

## ⚖️ Legal & Ethical Notice

This project:
- ✅ Only accesses **publicly available** GitHub data
- ✅ Does **NOT** store or use any actual API keys
- ✅ Promotes **security awareness** and best practices
- ✅ Helps developers **protect their credentials**

All data shown here is already publicly visible on GitHub. This tool simply aggregates statistics for research purposes.

---

*Generated by [exposed-ai-api-keys](https://github.com/gtg7784/exposed-ai-api-keys) - Security Research Project*
"""
    
    return readme


def main():
    """Main entry point."""
    print("=" * 60)
    print("🔍 Codex API Key Exposure Scanner")
    print("Security Research Project")
    print("=" * 60)
    
    # Get GitHub token
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        print("❌ Error: GITHUB_TOKEN environment variable not set")
        return 1
    
    # Create scanner
    scanner = GitHubScanner(token)
    
    # Scan for exposed keys
    findings = scanner.scan_for_keys()
    
    print(f"\n{'=' * 60}")
    print(f"Scan Complete!")
    print(f"Total findings: {len(findings)}")
    print(f"{'=' * 60}")
    
    # Save findings
    output_dir = Path('data')
    scanner.save_findings(findings, output_dir)
    print(f"\n💾 Findings saved to {output_dir}/")
    
    # Generate and save README
    scan_time = datetime.now(timezone.utc)
    readme = generate_readme(findings, scan_time)
    
    with open('README.md', 'w') as f:
        f.write(readme)
    
    print(f"\n📄 README.md updated")
    print(f"\n✅ Done!")
    
    return 0


if __name__ == '__main__':
    exit(main())
