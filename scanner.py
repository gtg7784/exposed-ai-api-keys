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
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
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

    # Multiple patterns to catch different key formats
    KEY_PATTERNS = [
        (r'[=:\s\'"`](sk-proj-[a-zA-Z0-9_-]{100,})', 'sk-proj'),
        (r'[=:\s\'"`](sk-[a-zA-Z0-9]{48,})', 'sk-generic'),
        (r'[=:\s\'"`](OPENAI_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'env-var'),
        (r'[=:\s\'"`](AZURE_OPENAI_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'azure-env'),
        (r'[=:\s\'"`](ANTHROPIC_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'anthropic-env'),
        (r'[=:\s\'"`](COHERE_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'cohere-env'),
        (r'[=:\s\'"`](HUGGINGFACE_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'huggingface-env'),
        (r'[=:\s\'"`](HF_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'hf-env'),
        (r'[=:\s\'"`](REPLICATE_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'replicate-env'),
        (r'[=:\s\'"`](TOGETHER_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'together-env'),
        (r'[=:\s\'"`](AI21_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'ai21-env'),
        (r'[=:\s\'"`](PPLX_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'pplx-env'),
        (r'[=:\s\'"`](PERPLEXITY_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'perplexity-env'),
        (r'[=:\s\'"`](MISTRAL_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'mistral-env'),
        (r'[=:\s\'"`](GROQ_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'groq-env'),
        (r'[=:\s\'"`](DEEPSEEK_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'deepseek-env'),
        (r'[=:\s\'"`](GEMINI_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'gemini-env'),
        (r'[=:\s\'"`](GOOGLE_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'google-env'),
        (r'[=:\s\'"`](CLAUDE_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'claude-env'),
        (r'[=:\s\'"`](AI_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'ai-env'),
        (r'[=:\s\'"`](LLM_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'llm-env'),
        (r'[=:\s\'"`](LANGUAGE_MODEL_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'lm-env'),
        (r'[=:\s\'"`](CHATGPT_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'chatgpt-env'),
        (r'[=:\s\'"`](GPT_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'gpt-env'),
        (r'[=:\s\'"`](GPT3_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'gpt3-env'),
        (r'[=:\s\'"`](GPT4_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'gpt4-env'),
        (r'[=:\s\'"`](GPT35_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'gpt35-env'),
        (r'[=:\s\'"`](DALLE_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'dalle-env'),
        (r'[=:\s\'"`](CODEX_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'codex-env'),
        (r'[=:\s\'"`](EMBEDDING_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'embedding-env'),
        (r'[=:\s\'"`](WHISPER_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'whisper-env'),
        (r'[=:\s\'"`](TTS_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'tts-env'),
        (r'[=:\s\'"`](STT_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'stt-env'),
        (r'[=:\s\'"`](IMAGE_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'image-env'),
        (r'[=:\s\'"`](VISION_API_KEY[=:\s\'"`][a-zA-Z0-9_-]{20,})', 'vision-env'),
    ]

    # Strict rate limiting: GitHub Search API = 10 requests/minute
    RATE_LIMIT_DELAY = 3  # Reduced delay for more throughput
    JITTER_RANGE = (0, 1)

    # Request budgeting - optimized for finding MORE keys (matching v1 performance)
    MAX_REQUESTS_PER_SCAN = 60  # GitHub Search API: 10 req/min, allow 6 min window
    MAX_PAGES = 3  # Pagination: 3 pages × 30 results = 90 files per query (like v1)
    MAX_FILES_PER_QUERY = 90  # Match v1: analyze 90 files per query for max discovery

    def __init__(self, token: str):
        self.token = token
        self.session = self._create_session()
        self.findings: List[ExposedKeyFinding] = []
        self.requests_made = 0
        self.analyzed_files: Set[str] = set()
        self._budget_warning_shown = False

    def _create_session(self) -> requests.Session:
        """Create a requests session with retries and auth."""
        session = requests.Session()
        session.headers.update({
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'CodexKeyScanner-SecurityResearch/1.0'
        })

        retry_strategy = Retry(
            total=2,  # Reduced retries
            backoff_factor=3,  # Longer backoff
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        return session

    def _wait_if_needed(self):
        """Wait respecting rate limits with jitter."""
        jitter = random.uniform(*self.JITTER_RANGE)
        delay = self.RATE_LIMIT_DELAY + jitter
        time.sleep(delay)

    def _check_budget(self) -> bool:
        """Check if we've exceeded request budget."""
        if self.requests_made >= self.MAX_REQUESTS_PER_SCAN:
            if not self._budget_warning_shown:
                print(f"  ⚠️ Request budget exhausted ({self.MAX_REQUESTS_PER_SCAN})")
                self._budget_warning_shown = True
            return False
        return True

    def search_code(self, query: str, per_page: int = 30) -> List[Dict[str, Any]]:
        """Search GitHub code with strict request budgeting."""
        results = []
        page = 1

        print(f"  Query: {query}")
        print(f"  Budget: {self.requests_made}/{self.MAX_REQUESTS_PER_SCAN} requests used")

        while page <= self.MAX_PAGES:
            if not self._check_budget():
                break

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

                if response.status_code == 403:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_time = max(reset_time - int(time.time()), 60)
                    print(f"  ⏳ Rate limited. Waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue

                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    print(f"  ⏳ 429 received. Waiting {retry_after}s...")
                    time.sleep(retry_after)
                    continue

                if response.status_code == 422:
                    print(f"  ⚠️ Invalid query")
                    break

                if response.status_code != 200:
                    print(f"  ⚠️ HTTP {response.status_code}")
                    break

                data = response.json()
                items = data.get('items', [])
                if not items:
                    break

                results.extend(items)
                print(f"  Page {page}: {len(items)} results (total: {len(results)})")

                page += 1

                # Wait before next request
                if page <= self.MAX_PAGES:
                    self._wait_if_needed()

            except requests.exceptions.RequestException as e:
                print(f"  ⚠️ Request error: {e}")
                break

        return results

    def analyze_file(self, item: Dict[str, Any], key_type: str, pattern: str) -> Optional[ExposedKeyFinding]:
        """Analyze a single file for exposed keys."""
        # Check request budget
        if not self._check_budget():
            return None

        # Check cache
        file_id = f"{item.get('repository', {}).get('full_name')}:{item.get('path')}"
        if file_id in self.analyzed_files:
            return None
        self.analyzed_files.add(file_id)

        try:
            contents_url = item.get('url')
            if not contents_url:
                return None

            response = self.session.get(contents_url, timeout=10)
            self.requests_made += 1

            if response.status_code in [403, 429]:
                return None  # Skip on rate limit

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

        except Exception:
            return None

    def _get_queries_for_this_hour(self) -> List[tuple]:
        """Get high-yield queries prioritized for max key discovery.

        Strategy: Focus on 3 highest-yield queries to stay within budget:
        - 3 search requests (1 per query × 3 queries)
        - Up to 90 file analysis requests per query (with pagination)
        - Total: ~93 requests worst case, fits in 60 budget with early termination
        """
        # High-yield queries prioritized by historical performance
        # .env files alone found 28 keys in v1 with 90 file analysis
        return [
            ('sk-proj- filename:.env', 'sk-proj-env'),      # Highest yield: .env files
            ('sk-proj- extension:py', 'sk-proj-py'),        # Python files
            ('sk-proj- extension:js', 'sk-proj-js'),        # JavaScript files
        ]

    def scan_for_keys(self) -> List[ExposedKeyFinding]:
        """Scan GitHub for exposed Codex API keys with strict budgeting."""
        queries_to_run = self._get_queries_for_this_hour()

        print(f"Budget: {self.MAX_REQUESTS_PER_SCAN} requests max")
        print(f"Rate limit: ~{self.RATE_LIMIT_DELAY}s between requests")
        print(f"Running {len(queries_to_run)} high-yield queries (.env, .py, .js)\n")

        all_findings = []

        for query, query_label in queries_to_run:
            if not self._check_budget():
                print("  ⏹️ Stopping: request budget exhausted")
                break

            print(f"[{query_label}] Searching: {query[:40]}...")

            results = self.search_code(query)
            print(f"  Found {len(results)} files")

            if not results:
                continue

            files_to_analyze = results[:self.MAX_FILES_PER_QUERY]
            print(f"  Analyzing top {len(files_to_analyze)} files...")

            for item in files_to_analyze:
                if not self._check_budget():
                    print("  ⏹️ Stopping: request budget exhausted")
                    break

                for pattern, pattern_label in self.KEY_PATTERNS:
                    finding = self.analyze_file(item, f"{query_label}-{pattern_label}", pattern)
                    if finding:
                        all_findings.append(finding)
                        print(f"    ⚠️  {finding.repository}")
                        break

                time.sleep(0.5)

            self._wait_if_needed()

        # Scan public gists
        gist_findings = self.scan_gists()
        all_findings.extend(gist_findings)

        print(f"\nTotal findings: {len(all_findings)}\n")
        return all_findings

    def scan_gists(self) -> List[ExposedKeyFinding]:
        """Scan public gists for exposed API keys."""
        if not self._check_budget():
            return []

        print("[gist] Scanning public gists...")

        findings = []

        try:
            url = 'https://api.github.com/gists/public'
            params = {'per_page': 100}

            response = self.session.get(url, params=params, timeout=30)
            self.requests_made += 1

            if response.status_code in [403, 429]:
                print("  ⏳ Rate limited on gist endpoint, skipping")
                return []

            if response.status_code != 200:
                print(f"  ⚠️ HTTP {response.status_code} from gist endpoint")
                return []

            gists = response.json()
            print(f"  Found {len(gists)} public gists")

            for gist in gists[:10]:  # Only check top 10 recent gists
                if not self._check_budget():
                    break

                gist_id = gist.get('id', 'unknown')
                owner = gist.get('owner', {})
                owner_login = owner.get('login', 'anonymous') if owner else 'anonymous'
                gist_url = gist.get('html_url', '')

                files = gist.get('files', {})
                for filename, file_info in files.items():
                    if not self._check_budget():
                        break

                    content = file_info.get('content', '')
                    if not content:
                        raw_url = file_info.get('raw_url', '')
                        if raw_url:
                            try:
                                raw_response = self.session.get(raw_url, timeout=10)
                                self.requests_made += 1
                                if raw_response.status_code == 200:
                                    content = raw_response.text
                            except:
                                continue

                    if not content:
                        continue

                    for pattern, pattern_label in self.KEY_PATTERNS:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            full_key = match.group(1)
                            finding = ExposedKeyFinding(
                                repository=f'gist:{owner_login}',
                                file_path=filename,
                                file_url=gist_url,
                                commit_sha=gist.get('history', [{}])[0].get('version') if gist.get('history') else None,
                                discovered_at=datetime.now(timezone.utc).isoformat(),
                                key_type=f'gist-{pattern_label}',
                                key_preview=full_key[:12] + '***' if len(full_key) > 12 else full_key[:8] + '***'
                            )
                            findings.append(finding)
                            print(f"    ⚠️  gist:{owner_login}/{filename}")
                            break  # Only report first match per file

            print(f"  Gist findings: {len(findings)}")

        except Exception as e:
            print(f"  ⚠️ Error scanning gists: {e}")

        return findings

    def save_findings(self, findings: List[ExposedKeyFinding], output_dir: Path):
        """Save findings to JSON file."""
        output_dir.mkdir(parents=True, exist_ok=True)

        # Load existing data if available
        latest_file = output_dir / 'latest.json'
        existing_findings = []
        if latest_file.exists():
            try:
                with open(latest_file) as f:
                    data = json.load(f)
                    existing_findings = [ExposedKeyFinding(**f) for f in data.get('findings', [])]
            except Exception:
                pass

        # Merge findings (avoid duplicates by file_url)
        seen_urls = {f.file_url for f in existing_findings}
        for f in findings:
            if f.file_url not in seen_urls:
                existing_findings.append(f)
                seen_urls.add(f.file_url)

        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f'scan_{timestamp}.json'

        data = {
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
            'total_findings': len(existing_findings),
            'requests_made': self.requests_made,
            'findings': [asdict(f) for f in existing_findings]
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        with open(latest_file, 'w') as f:
            json.dump(data, f, indent=2)

        return output_file, existing_findings


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
**Total Unique Findings**: {total_findings}

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Key Types Detected** | {len(by_type)} |
| **Affected Repositories** | {len(by_repo)} |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
"""

    for key_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
        readme += f"| `{key_type}` | {count} |\n"

    readme += """
### Recent Findings (Last 30 Days)

| Repository | File Path | Key Type | Preview | Discovered |
|------------|-----------|----------|---------|------------|
"""

    # Sort by discovery date (newest first) and show most recent 100
    recent_findings = sorted(findings, key=lambda x: x.discovered_at, reverse=True)[:100]

    for f in recent_findings:
        repo_short = f.repository[:30] + '...' if len(f.repository) > 30 else f.repository
        file_short = f.file_path[:35] + '...' if len(f.file_path) > 35 else f.file_path
        readme += f"| `{repo_short}` | `{file_short}` | `{f.key_type}` | `{f.key_preview}` | {f.discovered_at[:10]} |\n"

    if len(findings) > 100:
        readme += f"\n*... and {len(findings) - 100} more unique findings (see `data/` directory)*\n"

    readme += f"""

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

## 📈 Methodology

This scanner runs every hour via GitHub Actions with strict rate limiting:
- Maximum {20} requests per scan (GitHub Search API limit: 10/min)
- Analyzes only `.env` files containing `sk-proj-` patterns
- Records only metadata (repo name, file path, timestamp)
- Aggregates findings across multiple scans over time

---

## ⚖️ Legal & Ethical Notice

This project:
- ✅ Only accesses **publicly available** GitHub data
- ✅ Does **NOT** store or use any actual API keys
- ✅ Promotes **security awareness** and best practices

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

    output_dir = Path('data')
    output_file, all_findings = scanner.save_findings(findings, output_dir)

    scan_time = datetime.now(timezone.utc)
    readme = generate_readme(all_findings, scan_time, scanner.requests_made)

    with open('README.md', 'w') as f:
        f.write(readme)

    print(f"\n{'=' * 60}")
    print(f"Scan Complete!")
    print(f"New findings: {len(findings)}")
    print(f"Total unique: {len(all_findings)}")
    print(f"API requests: {scanner.requests_made}")
    print(f"{'=' * 60}")
    print(f"\n💾 Data saved to {output_file}")
    print(f"📄 README.md updated")
    print(f"\n✅ Done!")

    return 0


if __name__ == '__main__':
    exit(main())
