# 🔍 Codex API Key Exposure Monitor

> **SECURITY RESEARCH PROJECT**: Automated monitoring of publicly exposed Codex API keys on GitHub

⚠️ **IMPORTANT**: This project is for **security research and awareness purposes only**.
- No actual API keys are stored or logged
- Only publicly visible metadata is collected
- Repository owners are encouraged to revoke exposed keys immediately

---

## 📊 Latest Scan Results

**Last Updated**: 2026-08-29 13:22:07 UTC
**API Requests Made**: 10
**Total Unique Findings**: 543

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Key Types Detected** | 47 |
| **Affected Repositories** | 119 |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
| `sk-proj-py-env-var` | 62 |
| `sk-proj-json-sk-generic` | 53 |
| `sk-proj-json-env-var` | 48 |
| `sk-proj-ts-anthropic-env` | 46 |
| `sk-proj-env-env-var` | 46 |
| `sk-proj-ts-env-var` | 27 |
| `sk-proj-json-anthropic-env` | 26 |
| `sk-proj-py-anthropic-env` | 23 |
| `sk-proj-py-sk-proj` | 17 |
| `sk-proj-env-sk-proj` | 16 |
| `sk-proj-yml-env-var` | 15 |
| `sk-proj-json-gemini-env` | 14 |
| `sk-proj-env-google-env` | 13 |
| `sk-proj-js-env-var` | 12 |
| `sk-proj-py-sk-generic` | 10 |
| `sk-proj-env-gemini-env` | 9 |
| `sk-proj-json-google-env` | 8 |
| `sk-proj-ts-sk-generic` | 8 |
| `sk-proj-yml-anthropic-env` | 7 |
| `sk-proj-json-sk-proj` | 6 |
| `sk-proj-yml-sk-generic` | 6 |
| `sk-proj-json-claude-env` | 6 |
| `sk-proj-js-anthropic-env` | 6 |
| `sk-proj-py-google-env` | 5 |
| `sk-proj-json-groq-env` | 5 |
| `sk-proj-json-deepseek-env` | 5 |
| `sk-proj-py-groq-env` | 5 |
| `sk-proj-yml-sk-proj` | 4 |
| `sk-proj-ts-google-env` | 4 |
| `sk-proj-js-sk-generic` | 4 |
| `sk-proj-json-embedding-env` | 3 |
| `sk-proj-py-gemini-env` | 3 |
| `sk-proj-js-sk-proj` | 2 |
| `sk-proj-yml-google-env` | 2 |
| `sk-proj-ts-claude-env` | 2 |
| `sk-proj-ts-deepseek-env` | 2 |
| `sk-proj-js-google-env` | 2 |
| `sk-proj-py-deepseek-env` | 2 |
| `sk-proj-json-llm-env` | 1 |
| `sk-proj-json-ai-env` | 1 |
| `sk-proj-ts-llm-env` | 1 |
| `sk-proj-env-llm-env` | 1 |
| `sk-proj-env-anthropic-env` | 1 |
| `sk-proj-env-deepseek-env` | 1 |
| `sk-proj-ts-mistral-env` | 1 |
| `sk-proj-py-hf-env` | 1 |
| `sk-proj-py-llm-env` | 1 |

### Recent Findings (Last 30 Days)

| Repository | File Path | Key Type | Preview | Discovered |
|------------|-----------|----------|---------|------------|
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
| `Abilityai/trinity` | `docs/testing/GEMINI_TESTING_PLAN.md` | `sk-proj-js-google-env` | `GOOGLE_API_K***` | 2026-08-29 |
| `Abilityai/trinity` | `docs/GEMINI_SUPPORT.md` | `sk-proj-js-google-env` | `GOOGLE_API_K***` | 2026-08-29 |
| `garrytan/gbrain` | `test/helpers/agent-harness.unit.tes...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `nexu-io/open-design` | `apps/daemon/tests/run-diagnostics.t...` | `sk-proj-ts-sk-generic` | `sk-aaaaaaaaa***` | 2026-08-29 |
| `QwenLM/qwen-code` | `docs/users/configuration/model-prov...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `Gitlawb/openclaude` | `src/utils/diagnostics/redaction.tes...` | `sk-proj-ts-mistral-env` | `MISTRAL_API_***` | 2026-08-29 |
| `Gitlawb/openclaude` | `ANDROID_INSTALL.md` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-08-29 |
| `Gitlawb/openclaude` | `.env.example` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `diegosouzapw/OmniRoute` | `tests/unit/piiReproduction.test.ts` | `sk-proj-ts-sk-generic` | `sk-123456789***` | 2026-08-29 |
| `diegosouzapw/OmniRoute` | `docker/devin-bridge/run-claude-live...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `diegosouzapw/OmniRoute` | `docker/devin-bridge/run-claude-e2e....` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-08-29 |
| `xenitV1/lemma` | `tests/memory/privacy.test.ts` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-08-25 |
| `odysseus-dev/odysseus` | `.env.example` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-08-13 |
| `github/gh-aw-firewall` | `docs/cloud-hypervisor-foundation.md` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-08-11 |
| `github/gh-aw-firewall` | `docs/firecracker-integration.md` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-08-10 |
| `langwatch/langwatch` | `sdks/typescript/src/cli/commands/__...` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-08-04 |
| `langwatch/langwatch` | `sdks/typescript/examples/evaluation...` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-08-04 |
| `langwatch/langwatch` | `sdks/typescript/__tests__/e2e/cli/g...` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-08-04 |
| `github/gh-aw-firewall` | `docs/authentication-architecture.md` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-08-04 |
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

*... and 443 more unique findings (see `data/` directory)*


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
