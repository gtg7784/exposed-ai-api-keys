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

    # Multiple search queries to find exposed keys across file types
    # Prioritized by likelihood of containing valid API keys
    SEARCH_QUERIES = [
        ('sk-proj-', 'sk-proj-generic'),
        ('sk-proj- filename:.env', 'sk-proj-env'),
        ('sk-proj- extension:py', 'sk-proj-py'),
        ('sk-proj- extension:js', 'sk-proj-js'),
        ('sk-proj- extension:ts', 'sk-proj-ts'),
        ('sk-proj- extension:json', 'sk-proj-json'),
        ('sk-proj- extension:yml', 'sk-proj-yml'),
        ('sk-proj- extension:yaml', 'sk-proj-yaml'),
        ('sk-proj- extension:sh', 'sk-proj-sh'),
        ('sk-proj- extension:bash', 'sk-proj-bash'),
        ('sk-proj- extension:zsh', 'sk-proj-zsh'),
        ('sk-proj- extension:md', 'sk-proj-md'),
        ('sk-proj- extension:txt', 'sk-proj-txt'),
        ('sk-proj- extension:toml', 'sk-proj-toml'),
        ('sk-proj- extension:ini', 'sk-proj-ini'),
        ('sk-proj- extension:cfg', 'sk-proj-cfg'),
        ('sk-proj- extension:conf', 'sk-proj-conf'),
        ('sk-proj- extension:config', 'sk-proj-config'),
        ('sk-proj- extension:properties', 'sk-proj-properties'),
        ('sk-proj- extension:xml', 'sk-proj-xml'),
        ('sk-proj- extension:sql', 'sk-proj-sql'),
        ('sk-proj- extension:ps1', 'sk-proj-ps1'),
        ('sk-proj- extension:bat', 'sk-proj-bat'),
        ('sk-proj- extension:cmd', 'sk-proj-cmd'),
        ('sk-proj- filename:.env', 'sk-proj-env'),
        ('sk-proj- filename:.env.local', 'sk-proj-env-local'),
        ('sk-proj- filename:.env.development', 'sk-proj-env-dev'),
        ('sk-proj- filename:.env.production', 'sk-proj-env-prod'),
        ('sk-proj- filename:.env.example', 'sk-proj-env-example'),
        ('sk-proj- filename:.bashrc', 'sk-proj-bashrc'),
        ('sk-proj- filename:.zshrc', 'sk-proj-zshrc'),
        ('sk-proj- filename:.bash_profile', 'sk-proj-bash-profile'),
        ('sk-proj- filename:.zsh_profile', 'sk-proj-zsh-profile'),
        ('sk-proj- filename:config.json', 'sk-proj-config-json'),
        ('sk-proj- filename:package.json', 'sk-proj-package-json'),
        ('sk-proj- filename:.gitconfig', 'sk-proj-gitconfig'),
        ('sk-proj- filename:.netrc', 'sk-proj-netrc'),
        ('sk-proj- filename:.npmrc', 'sk-proj-npmrc'),
        ('sk-proj- filename:.pypirc', 'sk-proj-pypirc'),
        ('sk-proj- filename:.dockerenv', 'sk-proj-dockerenv'),
        ('sk-proj- filename:docker-compose', 'sk-proj-docker-compose'),
        ('sk-proj- filename:Dockerfile', 'sk-proj-dockerfile'),
        ('sk-proj- filename:README', 'sk-proj-readme'),
        ('sk-proj- filename:CHANGELOG', 'sk-proj-changelog'),
        ('sk-proj- filename:LICENSE', 'sk-proj-license'),
        ('sk-proj- filename:Makefile', 'sk-proj-makefile'),
        ('sk-proj- filename:CMakeLists.txt', 'sk-proj-cmake'),
        ('sk-proj- filename:requirements.txt', 'sk-proj-requirements'),
        ('sk-proj- filename:package-lock.json', 'sk-proj-package-lock'),
        ('sk-proj- filename:yarn.lock', 'sk-proj-yarn-lock'),
        ('sk-proj- filename:Pipfile', 'sk-proj-pipfile'),
        ('sk-proj- filename:poetry.lock', 'sk-proj-poetry-lock'),
        ('sk-proj- filename:Gemfile', 'sk-proj-gemfile'),
        ('sk-proj- filename:Gemfile.lock', 'sk-proj-gemfile-lock'),
        ('sk-proj- filename:composer.json', 'sk-proj-composer'),
        ('sk-proj- filename:composer.lock', 'sk-proj-composer-lock'),
        ('sk-proj- filename:.htaccess', 'sk-proj-htaccess'),
        ('sk-proj- filename:.htpasswd', 'sk-proj-htpasswd'),
        ('sk-proj- filename:id_rsa', 'sk-proj-id-rsa'),
        ('sk-proj- filename:id_dsa', 'sk-proj-id-dsa'),
        ('sk-proj- filename:id_ecdsa', 'sk-proj-id-ecdsa'),
        ('sk-proj- filename:id_ed25519', 'sk-proj-id-ed25519'),
        ('sk-proj- filename:.ssh/config', 'sk-proj-ssh-config'),
        ('sk-proj- filename:.pgpass', 'sk-proj-pgpass'),
        ('sk-proj- filename:.my.cnf', 'sk-proj-my-cnf'),
        ('sk-proj- filename:mongorc.js', 'sk-proj-mongorc'),
        ('sk-proj- filename:.rediscli', 'sk-proj-rediscli'),
        ('sk-proj- filename:aws/config', 'sk-proj-aws-config'),
        ('sk-proj- filename:aws/credentials', 'sk-proj-aws-credentials'),
        ('sk-proj- filename:.boto', 'sk-proj-boto'),
        ('sk-proj- filename:.s3cfg', 'sk-proj-s3cfg'),
        ('sk-proj- filename:.kube/config', 'sk-proj-kube-config'),
        ('sk-proj- filename:.helm/config', 'sk-proj-helm-config'),
        ('sk-proj- filename:.terraformrc', 'sk-proj-terraformrc'),
        ('sk-proj- filename:terraform.tfstate', 'sk-proj-tfstate'),
        ('sk-proj- filename:.terraform.lock.hcl', 'sk-proj-tf-lock'),
        ('sk-proj- filename:firebase.json', 'sk-proj-firebase'),
        ('sk-proj- filename:google-services.json', 'sk-proj-google-services'),
        ('sk-proj- filename:Info.plist', 'sk-proj-info-plist'),
        ('sk-proj- filename:AndroidManifest.xml', 'sk-proj-android-manifest'),
        ('sk-proj- filename:strings.xml', 'sk-proj-strings-xml'),
        ('sk-proj- filename:Localizable.strings', 'sk-proj-localizable'),
        ('sk-proj- filename:fastlane/Fastfile', 'sk-proj-fastfile'),
        ('sk-proj- filename:.fastlane/config', 'sk-proj-fastlane-config'),
        ('sk-proj- filename:.circleci/config.yml', 'sk-proj-circleci'),
        ('sk-proj- filename:.travis.yml', 'sk-proj-travis'),
        ('sk-proj- filename:.github/workflows', 'sk-proj-github-workflow'),
        ('sk-proj- filename:Jenkinsfile', 'sk-proj-jenkinsfile'),
        ('sk-proj- filename:gitlab-ci.yml', 'sk-proj-gitlab-ci'),
        ('sk-proj- filename:azure-pipelines.yml', 'sk-proj-azure-pipelines'),
        ('sk-proj- filename:bitbucket-pipelines.yml', 'sk-proj-bitbucket-pipelines'),
        ('sk-proj- filename:appveyor.yml', 'sk-proj-appveyor'),
        ('sk-proj- filename:.drone.yml', 'sk-proj-drone'),
        ('sk-proj- filename:wercker.yml', 'sk-proj-wercker'),
        ('sk-proj- filename:codeship-steps.yml', 'sk-proj-codeship'),
        ('sk-proj- filename:shippable.yml', 'sk-proj-shippable'),
        ('sk-proj- filename:snapcraft.yaml', 'sk-proj-snapcraft'),
        ('sk-proj- filename:app.yaml', 'sk-proj-app-engine'),
        ('sk-proj- filename:app.json', 'sk-proj-app-json'),
        ('sk-proj- filename:manifest.json', 'sk-proj-manifest'),
        ('sk-proj- filename:web.config', 'sk-proj-web-config'),
        ('sk-proj- filename:application.yml', 'sk-proj-application-yml'),
        ('sk-proj- filename:application.properties', 'sk-proj-application-props'),
        ('sk-proj- filename:bootstrap.yml', 'sk-proj-bootstrap-yml'),
        ('sk-proj- filename:bootstrap.properties', 'sk-proj-bootstrap-props'),
        ('sk-proj- filename:logback.xml', 'sk-proj-logback'),
        ('sk-proj- filename:log4j.xml', 'sk-proj-log4j'),
        ('sk-proj- filename:log4j.properties', 'sk-proj-log4j-props'),
        ('sk-proj- filename:logging.properties', 'sk-proj-logging'),
        ('sk-proj- filename:hibernate.cfg.xml', 'sk-proj-hibernate'),
        ('sk-proj- filename:persistence.xml', 'sk-proj-persistence'),
        ('sk-proj- filename:orm.xml', 'sk-proj-orm'),
        ('sk-proj- filename:jboss-web.xml', 'sk-proj-jboss-web'),
        ('sk-proj- filename:web.xml', 'sk-proj-web-xml'),
        ('sk-proj- filename:context.xml', 'sk-proj-context-xml'),
        ('sk-proj- filename:server.xml', 'sk-proj-server-xml'),
        ('sk-proj- filename:tomcat-users.xml', 'sk-proj-tomcat-users'),
        ('sk-proj- filename:catalina.properties', 'sk-proj-catalina'),
        ('sk-proj- filename:setenv.sh', 'sk-proj-setenv'),
        ('sk-proj- filename:setenv.bat', 'sk-proj-setenv-bat'),
        ('sk-proj- filename:gradlew', 'sk-proj-gradlew'),
        ('sk-proj- filename:gradlew.bat', 'sk-proj-gradlew-bat'),
        ('sk-proj- filename:gradle.properties', 'sk-proj-gradle-props'),
        ('sk-proj- filename:build.gradle', 'sk-proj-build-gradle'),
        ('sk-proj- filename:settings.gradle', 'sk-proj-settings-gradle'),
        ('sk-proj- filename:pom.xml', 'sk-proj-pom'),
        ('sk-proj- filename:build.xml', 'sk-proj-build-xml'),
        ('sk-proj- filename:ivy.xml', 'sk-proj-ivy'),
        ('sk-proj- filename:ivysettings.xml', 'sk-proj-ivysettings'),
        ('sk-proj- filename:project.clj', 'sk-proj-clojure'),
        ('sk-proj- filename:build.boot', 'sk-proj-boot'),
        ('sk-proj- filename:deps.edn', 'sk-proj-deps'),
        ('sk-proj- filename:shadow-cljs.edn', 'sk-proj-shadow'),
        ('sk-proj- filename:package.cljs', 'sk-proj-cljs'),
        ('sk-proj- filename:shadow-cljs.edn', 'sk-proj-shadow-cljs'),
    ]

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
    RATE_LIMIT_DELAY = 6  # 6 seconds = 10 requests/minute (at the limit)
    JITTER_RANGE = (0, 2)

    # Request budgeting
    MAX_REQUESTS_PER_SCAN = 30  # Slightly increased for multiple queries
    MAX_PAGES = 1  # Only 1 page per query to stay under limits
    MAX_FILES_PER_QUERY = 5  # Analyze fewer files per query

    def __init__(self, token: str):
        self.token = token
        self.session = self._create_session()
        self.findings: List[ExposedKeyFinding] = []
        self.requests_made = 0
        self.analyzed_files: Set[str] = set()  # Cache to avoid re-analysis

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
            print(f"  ⚠️ Request budget exhausted ({self.MAX_REQUESTS_PER_SCAN})")
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

    def scan_for_keys(self) -> List[ExposedKeyFinding]:
        """Scan GitHub for exposed Codex API keys with strict budgeting."""
        print(f"Budget: {self.MAX_REQUESTS_PER_SCAN} requests max")
        print(f"Rate limit: ~{self.RATE_LIMIT_DELAY}s between requests\n")

        all_findings = []

        for query, query_label in self.SEARCH_QUERIES:
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

                time.sleep(1)

            is_last_query = (query, query_label) == self.SEARCH_QUERIES[-1]
            if not is_last_query:
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
