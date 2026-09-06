# 🔍 Codex API Key Exposure Monitor

> **SECURITY RESEARCH PROJECT**: Automated monitoring of publicly exposed Codex API keys on GitHub

⚠️ **IMPORTANT**: This project is for **security research and awareness purposes only**.
- No actual API keys are stored or logged
- Only publicly visible metadata is collected
- Repository owners are encouraged to revoke exposed keys immediately

---

## 📊 Latest Scan Results

**Last Updated**: 2026-09-06 22:19:37 UTC
**API Requests Made**: 10
**Total Unique Findings**: 575

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Key Types Detected** | 49 |
| **Affected Repositories** | 131 |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
| `sk-proj-py-env-var` | 62 |
| `sk-proj-json-env-var` | 60 |
| `sk-proj-json-sk-generic` | 55 |
| `sk-proj-env-env-var` | 50 |
| `sk-proj-ts-anthropic-env` | 46 |
| `sk-proj-json-anthropic-env` | 28 |
| `sk-proj-ts-env-var` | 27 |
| `sk-proj-py-anthropic-env` | 23 |
| `sk-proj-py-sk-proj` | 17 |
| `sk-proj-env-sk-proj` | 16 |
| `sk-proj-yml-env-var` | 15 |
| `sk-proj-json-gemini-env` | 14 |
| `sk-proj-js-env-var` | 13 |
| `sk-proj-env-google-env` | 13 |
| `sk-proj-py-sk-generic` | 10 |
| `sk-proj-env-gemini-env` | 9 |
| `sk-proj-yml-sk-proj` | 8 |
| `sk-proj-json-google-env` | 8 |
| `sk-proj-ts-sk-generic` | 8 |
| `sk-proj-yml-sk-generic` | 7 |
| `sk-proj-yml-anthropic-env` | 7 |
| `sk-proj-json-sk-proj` | 6 |
| `sk-proj-json-claude-env` | 6 |
| `sk-proj-js-anthropic-env` | 6 |
| `sk-proj-py-google-env` | 5 |
| `sk-proj-json-groq-env` | 5 |
| `sk-proj-json-deepseek-env` | 5 |
| `sk-proj-py-groq-env` | 5 |
| `sk-proj-ts-google-env` | 4 |
| `sk-proj-js-sk-generic` | 4 |
| `sk-proj-env-anthropic-env` | 4 |
| `sk-proj-json-embedding-env` | 3 |
| `sk-proj-py-gemini-env` | 3 |
| `sk-proj-js-sk-proj` | 2 |
| `sk-proj-yml-google-env` | 2 |
| `sk-proj-ts-claude-env` | 2 |
| `sk-proj-ts-deepseek-env` | 2 |
| `sk-proj-js-google-env` | 2 |
| `sk-proj-py-deepseek-env` | 2 |
| `sk-proj-env-sk-generic` | 2 |
| `sk-proj-json-llm-env` | 1 |
| `sk-proj-json-ai-env` | 1 |
| `sk-proj-ts-llm-env` | 1 |
| `sk-proj-env-llm-env` | 1 |
| `sk-proj-env-deepseek-env` | 1 |
| `sk-proj-ts-mistral-env` | 1 |
| `sk-proj-py-hf-env` | 1 |
| `sk-proj-py-llm-env` | 1 |
| `sk-proj-yml-huggingface-env` | 1 |

### Recent Findings (Last 30 Days)

| Repository | File Path | Key Type | Preview | Discovered |
|------------|-----------|----------|---------|------------|
| `cisco-ai-defense/defenseclaw` | `internal/scanoutput/redaction_test....` | `sk-proj-json-sk-generic` | `sk-test12345***` | 2026-09-02 |
| `cisco-ai-defense/defenseclaw` | `internal/gateway/api_codescan_test....` | `sk-proj-json-sk-generic` | `sk-test12345***` | 2026-09-02 |
| `Secure-Vector/securevector-ai-...` | `tests/unit/plugins/cursor/decide.te...` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-08-30 |
| `jmanhype/MCPhoenix` | `.env.example` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-08-30 |
| `openai/openai-cookbook` | `examples/vector_databases/qdrant/QA...` | `sk-proj-env-sk-generic` | `sk-xxxxxxxxx***` | 2026-08-30 |
| `openai/openai-cookbook` | `examples/vector_databases/chroma/hy...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-08-30 |
| `openai/openai-cookbook` | `examples/vector_databases/analyticd...` | `sk-proj-env-sk-generic` | `sk-xxxxxxxxx***` | 2026-08-30 |
| `IBM/mcp-context-forge` | `mcp-servers/python/mcp_eval_server/...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-08-30 |
| `anthropics/claude-cookbooks` | `third_party/ElevenLabs/.env.example` | `sk-proj-env-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-30 |
| `anthropics/claude-cookbooks` | `skills/.env.example` | `sk-proj-env-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-30 |
| `anthropics/claude-cookbooks` | `claude_agent_sdk/hosting/.env.examp...` | `sk-proj-env-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-30 |
| `VoltAgent/voltagent` | `examples/with-xquik-tools/README.md` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-08-30 |
| `siabang35/zega.ai` | `apps/api/.env.example` | `sk-proj-yml-huggingface-env` | `HUGGINGFACE_***` | 2026-08-29 |
| `PeterGachuru/Myfuture-Question...` | `src/main/resources/application.yml` | `sk-proj-yml-sk-proj` | `sk-proj-StKm***` | 2026-08-29 |
| `PeterGachuru/Myfuture-Question...` | `src/main/java/ke/co/myfuture/Myfutu...` | `sk-proj-yml-sk-proj` | `sk-proj-StKm***` | 2026-08-29 |
| `Dery-byte/schoolbackend` | `target/classes/application-dev.yml` | `sk-proj-yml-sk-proj` | `sk-proj-6Ya7***` | 2026-08-29 |
| `Dery-byte/schoolbackend` | `src/main/resources/application-dev....` | `sk-proj-yml-sk-proj` | `sk-proj-6Ya7***` | 2026-08-29 |
| `cipher982/longhouse` | `server/tests_lite/test_embeddings.p...` | `sk-proj-yml-sk-generic` | `sk-abc123456***` | 2026-08-29 |
| `raycast/extensions` | `extensions/ai-voice-studio/scripts/...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `maximhq/bifrost` | `tests/e2e/clis/reasoningreplay_test...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `maximhq/bifrost` | `docs/cli-agents/qwen-code.mdx` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `777genius/agent-teams-ai` | `test/main/services/team/TeamLaunchF...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `777genius/agent-teams-ai` | `test/main/features/runtime-provider...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `777genius/agent-teams-ai` | `test/main/features/runtime-provider...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `777genius/agent-teams-ai` | `src/features/member-log-stream/main...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `vellum-ai/vellum-assistant` | `packages/electron-desktop/src/redac...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `openclaw/openclaw` | `test/scripts/ci-hydrate-testbox-env...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `openclaw/openclaw` | `src/agents/embedded-agent-runner/te...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `openclaw/openclaw` | `scripts/test-live-acp-bind-docker.s...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `openclaw/openclaw` | `extensions/qa-lab/src/suite-launch....` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `openclaw/openclaw` | `extensions/codex/src/app-server/eve...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `openclaw/openclaw` | `examples/ai-chat/README.md` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `vectorize-io/hindsight` | `hindsight-docs/src/pages/cookbook/a...` | `sk-proj-py-llm-env` | `LLM_API_KEY=***` | 2026-08-29 |
| `vectorize-io/hindsight` | `hindsight-docs/src/pages/cookbook/a...` | `sk-proj-py-groq-env` | `GROQ_API_KEY***` | 2026-08-29 |
| `NVIDIA/NemoClaw` | `test/generation/post-merge-docs.tes...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `NVIDIA/NemoClaw` | `test/e2e/live/hermes-sandbox-secret...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `NVIDIA/NemoClaw` | `test/agents/hermes/hermes-start.tes...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `NVIDIA/NemoClaw` | `src/lib/onboard/command.test.ts` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `NVIDIA/NemoClaw` | `src/lib/actions/sandbox/gateway-wed...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `PostHog/posthog` | `ee/settings.py` | `sk-proj-py-gemini-env` | `GEMINI_API_K***` | 2026-08-29 |
| `davila7/claude-code-templates` | `dashboard/public/component-content/...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `davila7/claude-code-templates` | `dashboard/public/component-content/...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `davila7/claude-code-templates` | `dashboard/public/component-content/...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `davila7/claude-code-templates` | `dashboard/public/component-content/...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `davila7/claude-code-templates` | `dashboard/public/component-content/...` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week8/community_contributions/hopeo...` | `sk-proj-py-deepseek-env` | `DEEPSEEK_API***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week8/community_contributions/haben...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week5/community-contributions/vic_k...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week5/community-contributions/touri...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week5/community-contributions/lukmo...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week5/community-contributions/geral...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week5/community-contributions/emmy/...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week5/community-contributions/abdus...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week5/community-contributions/James...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week4/community-contributions/haben...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week4/community-contributions/haben...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week4/community-contributions/emmy/...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week4/community-contributions/ai_do...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week2/community-contributions/techn...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week2/community-contributions/solis...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week2/community-contributions/salah...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week2/community-contributions/salah...` | `sk-proj-py-gemini-env` | `GEMINI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week2/community-contributions/hopeo...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week2/community-contributions/haben...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week2/community-contributions/haben...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week2/community-contributions/Vatsa...` | `sk-proj-py-gemini-env` | `GEMINI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week2/community-contributions/AI Go...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week2/community-contributions/3_way...` | `sk-proj-py-deepseek-env` | `DEEPSEEK_API***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/toey_...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/toey_...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/toey_...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/toey_...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/tech_...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/solis...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/santc...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/basan...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/ai_cl...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/Yesh_...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/Samue...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/Recip...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/Nawal...` | `sk-proj-py-groq-env` | `GROQ_API_KEY***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `week1/community-contributions/AI_Pr...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `setup/SETUP-new.md` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `community-contributions/shabsi4u/sy...` | `sk-proj-py-hf-env` | `HF_API_KEY=y***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `community-contributions/keshav_awas...` | `sk-proj-py-groq-env` | `GROQ_API_KEY***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `community-contributions/json_respon...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `community-contributions/fbrynmghni/...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `community-contributions/faraz-llm-e...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `community-contributions/TV_show_rec...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `community-contributions/Arjav014/Pe...` | `sk-proj-py-groq-env` | `GROQ_API_KEY***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `community-contributions/Arjav014/AI...` | `sk-proj-py-google-env` | `GOOGLE_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `community-contributions/Arjav014/AI...` | `sk-proj-py-google-env` | `GOOGLE_API_K***` | 2026-08-29 |
| `ed-donner/llm_engineering` | `community-contributions/Arjav014/AI...` | `sk-proj-py-groq-env` | `GROQ_API_KEY***` | 2026-08-29 |
| `arcahyadi/odysseus` | `.env.example` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `odysseus-dev/odysseus-current` | `.env.example` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `Abilityai/trinity` | `tests/unit/test_credential_sanitize...` | `sk-proj-js-sk-generic` | `sk-keyabcdef***` | 2026-08-29 |
| `Abilityai/trinity` | `tests/unit/test_credential_sanitize...` | `sk-proj-js-sk-generic` | `sk-keyabcdef***` | 2026-08-29 |
| `Abilityai/trinity` | `tests/unit/test_1870_completed_turn...` | `sk-proj-js-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `Abilityai/trinity` | `tests/unit/test_1673_execution_erro...` | `sk-proj-js-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `Abilityai/trinity` | `tests/unit/test_1661_sanitizer_line...` | `sk-proj-js-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |

*... and 475 more unique findings (see `data/` directory)*


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
