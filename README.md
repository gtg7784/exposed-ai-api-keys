# 🔍 Codex API Key Exposure Monitor

> **SECURITY RESEARCH PROJECT**: Automated monitoring of publicly exposed Codex API keys on GitHub

⚠️ **IMPORTANT**: This project is for **security research and awareness purposes only**.
- No actual API keys are stored or logged
- Only publicly visible metadata is collected
- Repository owners are encouraged to revoke exposed keys immediately

---

## 📊 Latest Scan Results

**Last Updated**: 2026-05-27 18:12:42 UTC
**API Requests Made**: 10
**Total Unique Findings**: 405

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Key Types Detected** | 39 |
| **Affected Repositories** | 82 |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
| `sk-proj-json-sk-generic` | 51 |
| `sk-proj-env-env-var` | 46 |
| `sk-proj-json-env-var` | 45 |
| `sk-proj-ts-anthropic-env` | 38 |
| `sk-proj-json-anthropic-env` | 24 |
| `sk-proj-py-env-var` | 19 |
| `sk-proj-py-anthropic-env` | 19 |
| `sk-proj-env-sk-proj` | 16 |
| `sk-proj-json-gemini-env` | 14 |
| `sk-proj-env-google-env` | 13 |
| `sk-proj-ts-env-var` | 12 |
| `sk-proj-py-sk-generic` | 10 |
| `sk-proj-py-sk-proj` | 9 |
| `sk-proj-js-env-var` | 9 |
| `sk-proj-env-gemini-env` | 9 |
| `sk-proj-json-google-env` | 8 |
| `sk-proj-json-claude-env` | 6 |
| `sk-proj-json-sk-proj` | 5 |
| `sk-proj-yml-env-var` | 5 |
| `sk-proj-json-groq-env` | 5 |
| `sk-proj-json-deepseek-env` | 5 |
| `sk-proj-ts-sk-generic` | 4 |
| `sk-proj-py-google-env` | 3 |
| `sk-proj-yml-sk-generic` | 3 |
| `sk-proj-yml-sk-proj` | 3 |
| `sk-proj-json-embedding-env` | 3 |
| `sk-proj-ts-google-env` | 3 |
| `sk-proj-js-sk-proj` | 2 |
| `sk-proj-js-anthropic-env` | 2 |
| `sk-proj-js-sk-generic` | 2 |
| `sk-proj-ts-claude-env` | 2 |
| `sk-proj-ts-deepseek-env` | 2 |
| `sk-proj-yml-anthropic-env` | 2 |
| `sk-proj-yml-google-env` | 1 |
| `sk-proj-json-llm-env` | 1 |
| `sk-proj-json-ai-env` | 1 |
| `sk-proj-ts-llm-env` | 1 |
| `sk-proj-env-llm-env` | 1 |
| `sk-proj-env-anthropic-env` | 1 |

### Recent Findings (Last 30 Days)

| Repository | File Path | Key Type | Preview | Discovered |
|------------|-----------|----------|---------|------------|
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
| `MervinPraison/PraisonAI` | `docker/bots/.env.template` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `MervinPraison/PraisonAI` | `docker/README.md` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `MervinPraison/PraisonAI` | `docker/.env.template` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `MervinPraison/PraisonAI` | `README.md` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `yusufkaraaslan/Skill_Seekers` | `docs/zh-CN/reference/ENVIRONMENT_VA...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `yusufkaraaslan/Skill_Seekers` | `docs/reference/ENVIRONMENT_VARIABLE...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-21 |
| `yusufkaraaslan/Skill_Seekers` | `docs/guides/MCP_SETUP.md` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `yusufkaraaslan/Skill_Seekers` | `docs/features/HOW_TO_GUIDES.md` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `yusufkaraaslan/Skill_Seekers` | `.env.example` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-21 |
| `binary-husky/gpt_academic` | `tests/test_key_pattern_manager.py` | `sk-proj-py-sk-proj` | `sk-proj-xx-x***` | 2026-05-21 |
| `binary-husky/gpt_academic` | `docs/use_vllm.md` | `sk-proj-py-sk-generic` | `sk-123456789***` | 2026-05-21 |
| `binary-husky/gpt_academic` | `docs/translate_english.json` | `sk-proj-py-sk-proj` | `sk-proj-xx-x***` | 2026-05-21 |
| `binary-husky/gpt_academic` | `docker-compose.yml` | `sk-proj-py-sk-generic` | `sk-o6JSoidyg***` | 2026-05-21 |
| `binary-husky/gpt_academic` | `config.py` | `sk-proj-py-sk-generic` | `sk-123456789***` | 2026-05-21 |
| `EvoMap/evolver` | `test/webuiObserver.test.js` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-05-20 |
| `cisco-ai-defense/defenseclaw` | `docs-site/data/policy-recipes.json` | `sk-proj-json-sk-generic` | `sk-aaaaaaaaa***` | 2026-05-20 |
| `openclaw/openclaw` | `src/agents/sandbox-create-args.test...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-05-20 |
| `forem/forem` | `spec/services/agent_session_parsers...` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-05-13 |
| `LeoYeAI/openclaw-master-skills` | `skills/openclaw-sec/src/patterns/se...` | `sk-proj-json-sk-generic` | `sk-xxxxxxxxx***` | 2026-05-13 |
| `LeoYeAI/openclaw-master-skills` | `skills/openclaw-sec/__tests__/integ...` | `sk-proj-json-sk-generic` | `sk-123456789***` | 2026-05-13 |
| `LeoYeAI/openclaw-master-skills` | `skills/openclaw-sec-plus/src/patter...` | `sk-proj-json-sk-generic` | `sk-xxxxxxxxx***` | 2026-05-13 |
| `openclaw/openclaw` | `src/daemon/systemd.test.ts` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-13 |
| `openclaw/openclaw` | `src/config/sessions/transcript-appe...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-05-13 |
| `openclaw/openclaw` | `src/agents/transcript-redact.test.t...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-05-13 |
| `openclaw/openclaw` | `scripts/e2e/openai-web-search-minim...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-05-13 |
| `openclaw/openclaw` | `scripts/e2e/openai-image-auth-docke...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-05-13 |
| `openclaw/openclaw` | `extensions/codex/src/app-server/eve...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-05-13 |
| `openclaw/openclaw` | `.github/workflows/openclaw-live-and...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-13 |
| `mrbrownnn/Lab-4_2A202600272` | `agent.py` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-12 |
| `ganeshkiran987/Simple_Chatbot_...` | `check.py` | `sk-proj-py-sk-proj` | `sk-proj-_CwI***` | 2026-05-10 |
| `ganeshkiran987/Simple_Chatbot_...` | `chatbot/chatbot.py` | `sk-proj-py-sk-proj` | `sk-proj-_CwI***` | 2026-05-10 |
| `sarthaksinghgaur/LLM-Powered-A...` | `README.md` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-05-10 |
| `autoppia/autoppia_web_agents_s...` | `autoppia_web_agents_subnet/opensour...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-05-10 |
| `promptfoo/promptfoo` | `site/docs/guides/evaluate-google-ad...` | `sk-proj-ts-google-env` | `GOOGLE_API_K***` | 2026-05-10 |
| `promptfoo/promptfoo` | `examples/integration-google-adk/REA...` | `sk-proj-ts-google-env` | `GOOGLE_API_K***` | 2026-05-10 |
| `tangle-network/dapp` | `scripts/agent-browser/run-wallet-fl...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-10 |
| `cisco-ai-defense/defenseclaw` | `cli/tests/test_cmd_setup_rotate_tok...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-05-10 |
| `MoetazAbdalla/Med-pol-report` | `tryy.py` | `sk-proj-py-sk-proj` | `sk-proj-_PEN***` | 2026-05-07 |
| `MoetazAbdalla/Med-pol-report` | `assets/api key` | `sk-proj-py-sk-proj` | `sk-proj-_PEN***` | 2026-05-07 |
| `grcengineering/how-to-harden` | `packs/anthropic-claude/api/hth-anth...` | `sk-proj-yml-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-07 |
| `grcengineering/how-to-harden` | `docs/_data/packs/anthropic-claude.y...` | `sk-proj-yml-anthropic-env` | `ANTHROPIC_AP***` | 2026-05-07 |
| `sammargolis/OpenScribe` | `docs/MEDASR-SETUP.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-26 |
| `sammargolis/OpenScribe` | `README.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-26 |
| `lekesiz/bilan-final-full` | `docs/GEMINI_API_KEY_SETUP.md` | `sk-proj-env-gemini-env` | `GEMINI_API_K***` | 2026-04-23 |
| `lekesiz/bilan-final-full` | `docs/ENV_VARIABLES.md` | `sk-proj-env-gemini-env` | `GEMINI_API_K***` | 2026-04-23 |
| `lekesiz/bilan-final-full` | `docs/DEPLOYMENT_CHECKLIST.md` | `sk-proj-env-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-23 |
| `lekesiz/bilan-final-full` | `backend/.env.example` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-23 |
| `tmotti77/myplat` | `SESSION_SUMMARY.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-23 |
| `tmotti77/myplat` | `RAILWAY_DEPLOY_GUIDE.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-23 |
| `tmotti77/myplat` | `QUICK_START.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-23 |
| `tmotti77/myplat` | `DEPLOYMENT_GUIDE.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-23 |

*... and 305 more unique findings (see `data/` directory)*


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
