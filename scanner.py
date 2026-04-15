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
    key_type: str
    key_preview: str


class GitHubScanner:
    """Scanner for finding exposed API keys on GitHub."""

    # Optimized search queries - more specific to reduce rate limiting
    SEARCH_QUERIES = [
        {
            'name': 'sk-proj-env',
            'query': 'sk-proj- filename:.env',
            'pattern': r'[=:\s\'"](sk-proj-[a-zA-Z0-9_-]{100,})'
        },
        {
            'name': 'sk-proj-py',
            'query': 'sk-proj- language:python',
            'pattern': r'[=:\s\'"](sk-proj-[a-zA-Z0-9_-]{100,})'
        },
        {
            'name': 'sk-proj-js',
            'query': 'sk-proj- language:javascript',
            'pattern': r'[=:\s\'"](sk-proj-[a-zA-Z0-9_-]{100,})'
        },
        {
            'name': 'sk-env',
            'query': 'sk- filename:.env',
            'pattern': r'[=:\s\'"](sk-[a-zA-Z0-9_-]{40,})'
        },
        {
            'name': 'openai-base64',
            'query': 'T3BlbkFJ',
            'pattern': r'(T3BlbkFJ[a-zA-Z0-9+/=]{20,})'
        },
    ]

    # Conservative rate limiting: GitHub Search API allows 10 requests/minute
    RATE_LIMIT_DELAY = 7  # seconds between requests (conservative)
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 2

    def __init__(self, token: str):
        self.token = token
        self.session = self._create_session()
        self.findings: List[ExposedKeyFinding] = []
        self.requests_made = 0

    def _create_session(self) -> requests.Session:
        """Create a requests session with retries and auth."""
        session = requests.Session()
        session.headers.update({
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'CodexKeyScanner-SecurityResearch/1.0'
        })

        retry_strategy = Retry(
            total=self.MAX_RETRIES,
            backoff_factor=self.BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        return session

    def _handle_rate_limit(self, response: requests.Response) -> bool:
        """Handle rate limit response. Returns True if we should retry."""
        if response.status_code == 403:
            remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))

            if remaining == 0:
                wait_time = max(reset_time - int(time.time()), 60)
                print(f"  ⏳ Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                return True

        if response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))
            print(f"  ⏳ Too many requests. Waiting {retry_after} seconds...")
            time.sleep(retry_after)
            return True

        return False

    def search_code(self, query: str, per_page: int = 30) -> List[Dict[str, Any]]:
        """Search GitHub code with the given query."""
        results = []
        page = 1
        max_pages = 3  # Reduced to avoid rate limits
        consecutive_errors = 0
        max_consecutive_errors = 2

        print(f"  Query: {query}")

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
                response = self.session.get(url, params=params, timeout=30)
                self.requests_made += 1

                # Handle rate limiting
                if response.status_code in [403, 429]:
                    if self._handle_rate_limit(response):
                        continue  # Retry after waiting
                    else:
                        break

                if response.status_code == 422:
                    print(f"  ⚠️ Invalid query: {query}")
                    break

                response.raise_for_status()
                data = response.json()

                items = data.get('items', [])
                if not items:
                    break

                results.extend(items)
                print(f"  Page {page}: {len(items)} results (total: {len(results)})")

                total_count = data.get('total_count', 0)
                if len(results) >= total_count or len(items) < per_page:
                    break

                page += 1
                consecutive_errors = 0

                # Check rate limit before next request
                remaining = int(response.headers.get('X-RateLimit-Remaining', 10))
                if remaining < 3:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_time = max(reset_time - int(time.time()), 0) + 5
                    print(f"  ⏳ Low rate limit. Waiting {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    time.sleep(self.RATE_LIMIT_DELAY)

            except requests.exceptions.RequestException as e:
                print(f"  ⚠️ Error: {e}")
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    print(f"  ❌ Too many errors, stopping this query")
                    break
                time.sleep(self.RATE_LIMIT_DELAY * 2)

        return results

    def analyze_file(self, item: Dict[str, Any], key_type: str, pattern: str) -> Optional[ExposedKeyFinding]:
        """Analyze a file for exposed keys."""
        try:
            contents_url = item.get('url')
            if not contents_url:
                return None

            response = self.session.get(contents_url, timeout=10)
            self.requests_made += 1

            if response.status_code == 403:
                self._handle_rate_limit(response)
                return None

            if response.status_code != 200:
                return None

            content_data = response.json()

            content = content_data.get('content', '')
            if content_data.get('encoding') == 'base64':
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                except Exception:
                    return None
            else:
                decoded = content

            matches = re.finditer(pattern, decoded)
            for match in matches:
                full_key = match.group(1)

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
            return None

    def scan_for_keys(self) -> List[ExposedKeyFinding]:
        """Scan GitHub for exposed Codex API keys."""
        all_findings = []

        print(f"Starting scan with {len(self.SEARCH_QUERIES)} queries...")
        print(f"Rate limit: 1 request per {self.RATE_LIMIT_DELAY} seconds\n")

        for search_config in self.SEARCH_QUERIES:
            name = search_config['name']
            query = search_config['query']
            pattern = search_config['pattern']

            print(f"[{name}] Scanning...")

            results = self.search_code(query)
            print(f"  Found {len(results)} files to analyze")

            analyzed = 0
            for item in results:
                finding = self.analyze_file(item, name, pattern)
                if finding:
                    all_findings.append(finding)
                    print(f"    ⚠️  {finding.repository}/{finding.file_path}")
                analyzed += 1

                # Brief pause between file analyses
                if analyzed % 5 == 0:
                    time.sleep(1)

            print(f"  Analyzed: {analyzed}, Findings: {len([f for f in all_findings if f.key_type == name])}")
            print()

        return all_findings

    def save_findings(self, findings: List[ExposedKeyFinding], output_dir: Path):
        """Save findings to JSON file."""
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f'scan_{timestamp}.json'

        data = {
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
            'total_findings': len(findings),
            'requests_made': self.requests_made,
            'findings': [asdict(f) for f in findings]
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        latest_file = output_dir / 'latest.json'
        with open(latest_file, 'w') as f:
            json.dump(data, f, indent=2)

        return output_file


def generate_readme(findings: List[ExposedKeyFinding], scan_time: datetime, requests_made: int) -> str:
    """Generate README with findings table."""

    total_findings = len(findings)
    by_type: Dict[str, int] = {}
    by_repo: Dict[str, int] = {}

    for f in findings:
        by_type[f.key_type] = by_type.get(f.key_type, 0) + 1
        by_repo[f.repository] = by_repo.get(f.repository, 0) + 1

    readme = f"""# 🔍 Codex API Key Exposure Monitor

> **SECURITY RESEARCH PROJECT**: Automated monitoring of publicly exposed Codex API keys on GitHub

⚠️ **IMPORTANT**: This project is for **security research and awareness purposes only**.
- No actual API keys are stored or logged
- Only publicly visible metadata is collected
- Repository owners are encouraged to revoke exposed keys immediately

---

## 📊 Latest Scan Results

**Last Updated**: {scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
**API Requests Made**: {requests_made}

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

    recent_findings = sorted(findings, key=lambda x: x.discovered_at, reverse=True)[:50]

    for f in recent_findings:
        repo_short = f.repository[:30] + '...' if len(f.repository) > 30 else f.repository
        file_short = f.file_path[:40] + '...' if len(f.file_path) > 40 else f.file_path
        readme += f"| `{repo_short}` | `{file_short}` | `{f.key_type}` | `{f.key_preview}` | {f.discovered_at[:10]} |\n"

    if len(findings) > 50:
        readme += f"\n*... and {len(findings) - 50} more findings (see `data/` directory)*\n"

    readme += """

---

## 🔒 For Repository Owners

If your repository appears in this list:

1. **Revoke the exposed key immediately** at https://platform.openai.com/api-keys
2. **Generate a new key** and update your applications
3. **Remove the exposed key from your repository history**:
   ```bash
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

**Key Patterns Monitored**:
- `sk-proj-*` (Project API keys)
- `sk-*` (Standard API keys)
- `T3BlbkFJ` (OpenAI Base64 identifier)

---

## ⚖️ Legal & Ethical Notice

This project:
- ✅ Only accesses **publicly available** GitHub data
- ✅ Does **NOT** store or use any actual API keys
- ✅ Promotes **security awareness** and best practices
- ✅ Helps developers **protect their credentials**

---

*Generated by free-codex-tokens - Security Research Project*
"""

    return readme


def main():
    """Main entry point."""
    print("=" * 60)
    print("🔍 Codex API Key Exposure Scanner")
    print("Security Research Project")
    print("=" * 60)

    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        print("❌ Error: GITHUB_TOKEN environment variable not set")
        return 1

    scanner = GitHubScanner(token)
    findings = scanner.scan_for_keys()

    print(f"\n{'=' * 60}")
    print(f"Scan Complete!")
    print(f"Total findings: {len(findings)}")
    print(f"API requests: {scanner.requests_made}")
    print(f"{'=' * 60}")

    output_dir = Path('data')
    scanner.save_findings(findings, output_dir)
    print(f"\n💾 Findings saved to {output_dir}/")

    scan_time = datetime.now(timezone.utc)
    readme = generate_readme(findings, scan_time, scanner.requests_made)

    with open('README.md', 'w') as f:
        f.write(readme)

    print(f"\n📄 README.md updated")
    print(f"\n✅ Done!")

    return 0


if __name__ == '__main__':
    exit(main())
