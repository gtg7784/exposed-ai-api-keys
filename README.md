# 🔍 Codex API Key Exposure Monitor

> **SECURITY RESEARCH PROJECT**: Automated monitoring of publicly exposed Codex API keys on GitHub

⚠️ **IMPORTANT**: This project is for **security research and awareness purposes only**.
- No actual API keys are stored or logged
- Only publicly visible metadata is collected
- Repository owners are encouraged to revoke exposed keys immediately

---

## 📊 Latest Scan Results

**Last Updated**: 2026-07-28 17:05:08 UTC
**API Requests Made**: 10
**Total Unique Findings**: 456

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Key Types Detected** | 40 |
| **Affected Repositories** | 106 |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
| `sk-proj-json-sk-generic` | 53 |
| `sk-proj-json-env-var` | 48 |
| `sk-proj-env-env-var` | 46 |
| `sk-proj-ts-anthropic-env` | 43 |
| `sk-proj-json-anthropic-env` | 26 |
| `sk-proj-ts-env-var` | 20 |
| `sk-proj-py-env-var` | 19 |
| `sk-proj-py-anthropic-env` | 19 |
| `sk-proj-py-sk-proj` | 17 |
| `sk-proj-env-sk-proj` | 16 |
| `sk-proj-json-gemini-env` | 14 |
| `sk-proj-env-google-env` | 13 |
| `sk-proj-yml-env-var` | 12 |
| `sk-proj-py-sk-generic` | 10 |
| `sk-proj-js-env-var` | 9 |
| `sk-proj-env-gemini-env` | 9 |
| `sk-proj-json-google-env` | 8 |
| `sk-proj-yml-anthropic-env` | 7 |
| `sk-proj-json-sk-proj` | 6 |
| `sk-proj-yml-sk-generic` | 6 |
| `sk-proj-json-claude-env` | 6 |
| `sk-proj-ts-sk-generic` | 6 |
| `sk-proj-json-groq-env` | 5 |
| `sk-proj-json-deepseek-env` | 5 |
| `sk-proj-yml-sk-proj` | 4 |
| `sk-proj-ts-google-env` | 4 |
| `sk-proj-py-google-env` | 3 |
| `sk-proj-json-embedding-env` | 3 |
| `sk-proj-js-anthropic-env` | 3 |
| `sk-proj-js-sk-proj` | 2 |
| `sk-proj-yml-google-env` | 2 |
| `sk-proj-js-sk-generic` | 2 |
| `sk-proj-ts-claude-env` | 2 |
| `sk-proj-ts-deepseek-env` | 2 |
| `sk-proj-json-llm-env` | 1 |
| `sk-proj-json-ai-env` | 1 |
| `sk-proj-ts-llm-env` | 1 |
| `sk-proj-env-llm-env` | 1 |
| `sk-proj-env-anthropic-env` | 1 |
| `sk-proj-env-deepseek-env` | 1 |

### Recent Findings (Last 30 Days)

| Repository | File Path | Key Type | Preview | Discovered |
|------------|-----------|----------|---------|------------|
| `soapbucket/sbproxy` | `examples/oidc/README.md` | `sk-proj-yml-anthropic-env` | `ANTHROPIC_AP***` | 2026-07-27 |
| `soapbucket/sbproxy` | `crates/sbproxy-core/src/server/ai_s...` | `sk-proj-yml-sk-generic` | `sk-aaaaaaaaa***` | 2026-07-27 |
| `spyrae/kronos-agent-os` | `tests/test_cassettes_tools.py` | `sk-proj-env-deepseek-env` | `DEEPSEEK_API***` | 2026-07-26 |
| `langwatch/langwatch` | `typescript-sdk/src/cli/commands/__t...` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-07-24 |
| `MihaiCiprianChezan/GREXIS` | `cli/scenarios/adversarial.py` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-07-21 |
| `KashifrazaBhat/AIT-LAB-REC0RD` | `task9c.py` | `sk-proj-py-sk-proj` | `sk-proj--xrD***` | 2026-07-19 |
| `KashifrazaBhat/AIT-LAB-REC0RD` | `task9b.py` | `sk-proj-py-sk-proj` | `sk-proj--xrD***` | 2026-07-19 |
| `KashifrazaBhat/AIT-LAB-REC0RD` | `task9.py` | `sk-proj-py-sk-proj` | `sk-proj--xrD***` | 2026-07-19 |
| `vellum-ai/vellum-assistant` | `clients/macos/src/main/redact.test....` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-07-16 |
| `Ibrahim-code21/flask-use-for-c...` | `tempCodeRunnerFile.py` | `sk-proj-py-sk-proj` | `sk-proj-_5Ne***` | 2026-07-15 |
| `Ibrahim-code21/flask-use-for-c...` | `main.py` | `sk-proj-py-sk-proj` | `sk-proj-_5Ne***` | 2026-07-15 |
| `cisco-ai-defense/defenseclaw` | `cli/tests/test_remediation_tui.py` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-07-11 |
| `mukiwu/tempo-term` | `src/modules/ai/lib/redact.test.ts` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-07-11 |
| `aygoun/ia-symbolic-app` | `docker-compose.yml` | `sk-proj-yml-sk-proj` | `sk-proj-_i0J***` | 2026-07-11 |
| `kiyoshi-work/app-server` | `docker-compose.yml` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-07-11 |
| `kiyoshi-work/app-server` | `docker-compose.dev.yml` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-07-11 |
| `aghaPathan/ai-dev-team` | `docs/DEPLOYMENT.md` | `sk-proj-yml-anthropic-env` | `ANTHROPIC_AP***` | 2026-07-11 |
| `promptfoo/promptfoo` | `src/app/src/stores/evalConfig.test....` | `sk-proj-ts-sk-generic` | `sk-structure***` | 2026-07-11 |
| `garrytan/gstack` | `.env.example` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-07-11 |
| `Trusera/ai-bom` | `tests/test_scanners/test_network_sc...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-07-10 |
| `Trusera/ai-bom` | `tests/fixtures/sample_env` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-07-10 |
| `Trusera/ai-bom` | `tests/conftest.py` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-07-10 |
| `Trusera/ai-bom` | `src/ai_bom/demo_data/.env.example` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-07-10 |
| `Trusera/ai-bom` | `examples/demo-project/.env.example` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-07-10 |
| `tonszazo-lang/raqqa` | `lmages.py.txt` | `sk-proj-py-sk-proj` | `sk-proj-cPyy***` | 2026-07-07 |
| `tonszazo-lang/raqqa` | `env` | `sk-proj-py-sk-proj` | `sk-proj-_nBz***` | 2026-07-07 |
| `tonszazo-lang/raqqa` | `config.py` | `sk-proj-py-sk-proj` | `sk-proj-_nBz***` | 2026-07-07 |
| `daintreehq/daintree` | `src/components/Settings/__tests__/E...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-07-04 |
| `github/gh-aw-firewall` | `containers/api-proxy/README.md` | `sk-proj-ts-google-env` | `GOOGLE_API_K***` | 2026-07-04 |
| `taracodlabs/aiden` | `tests/v4/mcp/credentialFilter.test....` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-07-02 |
| `luisfer/ubon` | `src/__tests__/security-rules.test.t...` | `sk-proj-ts-sk-generic` | `sk-xxxxxxxxx***` | 2026-06-28 |
| `dinosn/leaklens` | `pkg/rule/rules/stabilityai.yml` | `sk-proj-yml-sk-generic` | `sk-AnmgropvA***` | 2026-06-22 |
| `dinosn/leaklens` | `pkg/rule/rules/openai.yml` | `sk-proj-yml-sk-generic` | `sk-mxIt5s1ty***` | 2026-06-22 |
| `dinosn/leaklens` | `pkg/rule/rules/google.yml` | `sk-proj-yml-google-env` | `GOOGLE_API_K***` | 2026-06-22 |
| `Molecule-AI/molecule-core` | `workspace-server/internal/handlers/...` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-06-12 |
| `Molecule-AI/molecule-core` | `workspace-server/internal/handlers/...` | `sk-proj-yml-anthropic-env` | `ANTHROPIC_AP***` | 2026-06-12 |
| `Molecule-AI/molecule-core` | `tests/e2e/test_staging_full_saas.sh` | `sk-proj-yml-anthropic-env` | `ANTHROPIC_AP***` | 2026-06-12 |
| `cisco-ai-defense/defenseclaw` | `internal/cli/scan_test.go` | `sk-proj-json-sk-generic` | `sk-test12345***` | 2026-06-12 |
| `github/gh-aw-firewall` | `docs/awf-config-spec.md` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-06-10 |
| `langwatch/langwatch` | `typescript-sdk/examples/evaluation/...` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-06-08 |
| `langwatch/langwatch` | `typescript-sdk/__tests__/e2e/cli/go...` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-06-08 |
| `langwatch/langwatch` | `docs/integration/typescript/guide.m...` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-06-08 |
| `langwatch/langwatch` | `docs/integration/python/integration...` | `sk-proj-yml-anthropic-env` | `ANTHROPIC_AP***` | 2026-06-08 |
| `zylos-ai/zylos-core` | `cli/lib/__tests__/runtime-launch.te...` | `sk-proj-js-anthropic-env` | `ANTHROPIC_AP***` | 2026-06-08 |
| `askalf/dario` | `src/live-fingerprint.ts` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-06-07 |
| `askalf/dario` | `CHANGELOG.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-06-07 |
| `enescingoz/awesome-n8n-templat...` | `AI product imagines.json` | `sk-proj-json-sk-proj` | `sk-proj-Iu52***` | 2026-06-06 |
| `ossf/malicious-packages` | `osv/withdrawn/npm/@shadanai/opencla...` | `sk-proj-json-sk-generic` | `sk-xRxGLtCkA***` | 2026-05-29 |
| `openclaw/openclaw` | `test/scripts/package-acceptance-wor...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-29 |
| `openclaw/openclaw` | `docs/install/fly.md` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-05-29 |
| `openclaw/openclaw` | `.github/actions/docker-e2e-plan/act...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-29 |
| `ruvnet/agentic-flow` | `docs/implementation/API_KEY_OVERRID...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docs/guides/STANDALONE_PROXY_GUIDE....` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docs/docker/DOCKER_DEPLOYMENT_GUIDE...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docs/archived/plans/requesty/02-arc...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docs/archived/V1.1.11_COMPLETE_VALI...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docs/archived/README_V1.1.11.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docs/DOCKER_DEPLOYMENT_GUIDE.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docker/configs/claude.env.template` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docker/QUICK_REFERENCE.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docker/Dockerfile.test-mcp-simple` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docker/Dockerfile.test-mcp-all-args` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docker/Dockerfile.test-complete` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docker/Dockerfile.test-cli-params` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docker/Dockerfile.test-agent-mgmt` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `docker/.env.example` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `agentic-flow/src/cli-standalone-pro...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `agentic-flow/src/cli-proxy.ts` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `agentic-flow/docs/plans/requesty/02...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `agentic-flow/docs/guides/STANDALONE...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `agentic-flow/docs/archived/V1.1.11_...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `agentic-flow/docs/archived/README_V...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `ruvnet/agentic-flow` | `agentic-flow/docker/test-instance/....` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-22 |
| `DragonJAR/n8n-workflows-esp` | `workflows/01312-WhatsApp-virtual-ag...` | `sk-proj-json-google-env` | `GOOGLE_API_K***` | 2026-05-21 |
| `rohitg00/agentmemory` | `test/fs-watcher.test.ts` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `NVIDIA/NemoClaw` | `src/lib/sandbox-base-image.test.ts` | `sk-proj-ts-sk-generic` | `sk-abcdef012***` | 2026-05-21 |
| `n8n-io/n8n` | `packages/@n8n/instance-ai/evaluatio...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `docs/blog/e2b-claude-code-sandbox/i...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `dashboard/public/blog/e2b-claude-co...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/skills/scientif...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/skills/scientif...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/skills/scientif...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/sandbox/e2b/cla...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/sandbox/e2b/.en...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/sandbox/docker/...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/sandbox/cloudfl...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/sandbox/cloudfl...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/sandbox/cloudfl...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/sandbox/cloudfl...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/components/sandbox/README....` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/.claude/sandbox/cloudflare...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/.claude/sandbox/cloudflare...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/.claude/sandbox/cloudflare...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `cli-tool/.claude/sandbox/cloudflare...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `davila7/claude-code-templates` | `.env.example` | `sk-proj-py-google-env` | `GOOGLE_API_K***` | 2026-05-21 |
| `MervinPraison/PraisonAI` | `src/praisonai/praisonai/cli/feature...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `MervinPraison/PraisonAI` | `src/praisonai/README.md` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `MervinPraison/PraisonAI` | `src/praisonai-ts/.env.example` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `MervinPraison/PraisonAI` | `examples/recipes/creator_suite/.env...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `MervinPraison/PraisonAI` | `docker/quick-start.sh` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |

*... and 356 more unique findings (see `data/` directory)*


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
- Maximum 20 requests per scan (GitHub Search API limit: 10/min)
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
