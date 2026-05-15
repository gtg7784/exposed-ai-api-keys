# 🔍 Codex API Key Exposure Monitor

> **SECURITY RESEARCH PROJECT**: Automated monitoring of publicly exposed Codex API keys on GitHub

⚠️ **IMPORTANT**: This project is for **security research and awareness purposes only**.
- No actual API keys are stored or logged
- Only publicly visible metadata is collected
- Repository owners are encouraged to revoke exposed keys immediately

---

## 📊 Latest Scan Results

**Last Updated**: 2026-05-15 16:58:49 UTC
**API Requests Made**: 10
**Total Unique Findings**: 339

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Key Types Detected** | 39 |
| **Affected Repositories** | 72 |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
| `sk-proj-json-sk-generic` | 50 |
| `sk-proj-env-env-var` | 46 |
| `sk-proj-json-env-var` | 45 |
| `sk-proj-json-anthropic-env` | 24 |
| `sk-proj-env-sk-proj` | 16 |
| `sk-proj-ts-anthropic-env` | 15 |
| `sk-proj-json-gemini-env` | 13 |
| `sk-proj-env-google-env` | 13 |
| `sk-proj-ts-env-var` | 11 |
| `sk-proj-env-gemini-env` | 9 |
| `sk-proj-js-env-var` | 8 |
| `sk-proj-py-sk-proj` | 7 |
| `sk-proj-json-google-env` | 7 |
| `sk-proj-py-sk-generic` | 7 |
| `sk-proj-json-claude-env` | 6 |
| `sk-proj-json-sk-proj` | 5 |
| `sk-proj-py-env-var` | 5 |
| `sk-proj-yml-env-var` | 5 |
| `sk-proj-json-groq-env` | 5 |
| `sk-proj-json-deepseek-env` | 5 |
| `sk-proj-yml-sk-generic` | 3 |
| `sk-proj-yml-sk-proj` | 3 |
| `sk-proj-json-embedding-env` | 3 |
| `sk-proj-ts-google-env` | 3 |
| `sk-proj-ts-sk-generic` | 3 |
| `sk-proj-js-sk-proj` | 2 |
| `sk-proj-py-google-env` | 2 |
| `sk-proj-py-anthropic-env` | 2 |
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
| `tmotti77/myplat` | `.env.production.template` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-23 |
| `AnalyseDeCircuit/oxideterm` | `src/test/ai/contextSanitizer.test.t...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-22 |
| `openclaw/skills` | `skills/yontlly/ai-test-platform/pro...` | `sk-proj-ts-deepseek-env` | `DEEPSEEK_API***` | 2026-04-22 |
| `openclaw/skills` | `skills/yontlly/ai-test-platform/pro...` | `sk-proj-ts-deepseek-env` | `DEEPSEEK_API***` | 2026-04-22 |
| `trf2-jus-br/apoia` | `README.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-22 |
| `openclaw/skills` | `skills/tayllisun/arshis-memory/scri...` | `sk-proj-ts-sk-generic` | `sk-moxcmniwc***` | 2026-04-22 |
| `openclaw/skills` | `skills/olveww-dot/auto-distill/scri...` | `sk-proj-ts-sk-generic` | `sk-kgvvlyeud***` | 2026-04-22 |
| `openclaw/skills` | `skills/nicemaths123/social-spy-moni...` | `sk-proj-ts-claude-env` | `CLAUDE_API_K***` | 2026-04-22 |
| `openclaw/skills` | `skills/nicemaths123/business-opport...` | `sk-proj-ts-claude-env` | `CLAUDE_API_K***` | 2026-04-22 |
| `ObjectWeaver/ObjectWeaver` | `.env.llm.example` | `sk-proj-env-llm-env` | `LLM_API_KEY=***` | 2026-04-22 |
| `DrHaitham/PenTest2.0` | `README.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-22 |
| `rockerritesh/vibe_coder` | `README.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-22 |
| `Ashish-Pandey62/Agentic-Deskto...` | `README.md` | `sk-proj-py-google-env` | `GOOGLE_API_K***` | 2026-04-21 |
| `mrahmdi/Thatis` | `main.py` | `sk-proj-py-sk-proj` | `sk-proj--S4Z***` | 2026-04-21 |
| `peterkrueck/Claude-Code-Develo...` | `hooks/config/sensitive-patterns.jso...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `Zie619/n8n-workflows` | `medcards-ai/.env.example` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-20 |
| `Zie619/n8n-workflows` | `ai-stack/README.md` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-20 |
| `Zie619/n8n-workflows` | `ai-stack/.env` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-20 |
| `darfaz/clawmoat` | `site/index.html` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `darfaz/clawmoat` | `docs/playground.html` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `apisec-inc/mcp-audit` | `docs/RISK_SCORING.md` | `sk-proj-js-sk-generic` | `sk-xxxxxxxxx***` | 2026-04-20 |
| `snailyp/apichecker` | `js/help-system.js` | `sk-proj-js-sk-generic` | `sk-xxxxxxxxx***` | 2026-04-20 |
| `superagent-ai/vibekit` | `templates/v0-clone/README.md` | `sk-proj-js-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-20 |
| `superagent-ai/vibekit` | `templates/codex-clone/README.md` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `superagent-ai/vibekit` | `docs/supported-sandboxes/cloudflare...` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `superagent-ai/vibekit` | `docs/sdk/secrets.mdx` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `superagent-ai/vibekit` | `docs/cli/environment-variables.mdx` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `lancedb/vectordb-recipes` | `examples/saas_examples/ts_example/l...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `lancedb/vectordb-recipes` | `examples/saas_examples/ts_example/h...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `lancedb/vectordb-recipes` | `applications/archived_applications/...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `website/docs/rag/voltagent.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `website/docs/rag/qdrant.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `website/docs/rag/pinecone.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `website/docs/rag/lancedb.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `website/docs/rag/chroma.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `website/blog/2025-04-26-peaka-mcp-v...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `website/blog/2025-04-25-what-is-an-...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `website/blog/2025-04-24-rag-chatbot...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `website/blog/2025-04-23-multi-agent...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-thinking-tool/README....` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-tavily-search/README....` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-tavily-search/.env.ex...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-research-assistant/RE...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-recipe-generator/READ...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-qdrant/.env.example` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-postgres/.env.example` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-pinecone/README.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-pinecone/.env.example` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-nestjs/.env.example` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-memory-rest-api/.env....` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-mcp-elicitation/READM...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-lancedb/.env.example` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-hugging-face-mcp/READ...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-composio-mcp/README.m...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-cloudflare-workers/RE...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-cerbos/README.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/with-ad-creator/README.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `VoltAgent/voltagent` | `examples/next-js-chatbot-starter-te...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-20 |
| `panaversity/learn-agentic-ai` | `backup_recent/07c_langgraph_functio...` | `sk-proj-env-google-env` | `GOOGLE_API_K***` | 2026-04-20 |
| `panaversity/learn-agentic-ai` | `backup_recent/07c_langgraph_functio...` | `sk-proj-env-google-env` | `GOOGLE_API_K***` | 2026-04-20 |
| `panaversity/learn-agentic-ai` | `backup_recent/07c_langgraph_functio...` | `sk-proj-env-google-env` | `GOOGLE_API_K***` | 2026-04-20 |
| `panaversity/learn-agentic-ai` | `backup_recent/07c_langgraph_functio...` | `sk-proj-env-google-env` | `GOOGLE_API_K***` | 2026-04-20 |
| `panaversity/learn-agentic-ai` | `backup_recent/07c_langgraph_functio...` | `sk-proj-env-google-env` | `GOOGLE_API_K***` | 2026-04-20 |
| `panaversity/learn-agentic-ai` | `backup_recent/07c_langgraph_functio...` | `sk-proj-env-google-env` | `GOOGLE_API_K***` | 2026-04-20 |
| `panaversity/learn-agentic-ai` | `backup_recent/07c_langgraph_functio...` | `sk-proj-env-google-env` | `GOOGLE_API_K***` | 2026-04-20 |
| `panaversity/learn-agentic-ai` | `backup_recent/07c_langgraph_functio...` | `sk-proj-env-google-env` | `GOOGLE_API_K***` | 2026-04-20 |

*... and 239 more unique findings (see `data/` directory)*


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
