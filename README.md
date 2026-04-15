# 🔍 Codex API Key Exposure Monitor

> **SECURITY RESEARCH PROJECT**: Automated monitoring of publicly exposed Codex API keys on GitHub

⚠️ **IMPORTANT**: This project is for **security research and awareness purposes only**.
- No actual API keys are stored or logged
- Only publicly visible metadata is collected
- Repository owners are encouraged to revoke exposed keys immediately

---

## 📊 Latest Scan Results

**Last Updated**: 2026-04-15 21:25:53 UTC
**API Requests Made**: 10
**Total Unique Findings**: 45

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Key Types Detected** | 16 |
| **Affected Repositories** | 30 |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
| `sk-proj-env-sk-proj` | 16 |
| `sk-proj-yml-env-var` | 5 |
| `sk-proj-ts-anthropic-env` | 4 |
| `sk-proj-yml-sk-generic` | 3 |
| `sk-proj-yml-sk-proj` | 3 |
| `sk-proj-py-sk-proj` | 2 |
| `sk-proj-js-sk-proj` | 2 |
| `sk-proj-env-env-var` | 2 |
| `sk-proj-js-env-var` | 1 |
| `sk-proj-json-env-var` | 1 |
| `sk-proj-json-sk-proj` | 1 |
| `sk-proj-json-sk-generic` | 1 |
| `sk-proj-json-gemini-env` | 1 |
| `sk-proj-py-env-var` | 1 |
| `sk-proj-py-google-env` | 1 |
| `sk-proj-yml-google-env` | 1 |

### Recent Findings (Last 30 Days)

| Repository | File Path | Key Type | Preview | Discovered |
|------------|-----------|----------|---------|------------|
| `jrmreis/cloudmart-kube-infra` | `group_vars/all.yml` | `sk-proj-yml-sk-proj` | `sk-proj--oC2***` | 2026-04-15 |
| `Meng-V/subject_heading` | `docs/QUICK_START.md` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-04-15 |
| `Meng-V/subject_heading` | `docs/DEVELOPER_SETUP.md` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-04-15 |
| `Meng-V/subject_heading` | `docs/DATA_INGESTION.md` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-04-15 |
| `Meng-V/subject_heading` | `docs/AWS_DEPLOYMENT.md` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-04-15 |
| `Meng-V/subject_heading` | `backend/.env.example` | `sk-proj-yml-env-var` | `OPENAI_API_K***` | 2026-04-15 |
| `ansh200516/AI-Fortress-Sentine...` | `docker-compose.yml` | `sk-proj-yml-sk-proj` | `sk-proj--0bJ***` | 2026-04-15 |
| `dromara/forest` | `forest-examples/example-chatgpt/tar...` | `sk-proj-yml-sk-proj` | `sk-proj-ioDY***` | 2026-04-15 |
| `praetorian-inc/titus` | `testdata/secrets/mixed-secrets.txt` | `sk-proj-yml-sk-generic` | `sk-xxxxxxxxx***` | 2026-04-15 |
| `praetorian-inc/titus` | `pkg/rule/rules/stabilityai.yml` | `sk-proj-yml-sk-generic` | `sk-AnmgropvA***` | 2026-04-15 |
| `praetorian-inc/titus` | `pkg/rule/rules/openai.yml` | `sk-proj-yml-sk-generic` | `sk-mxIt5s1ty***` | 2026-04-15 |
| `praetorian-inc/titus` | `pkg/rule/rules/google.yml` | `sk-proj-yml-google-env` | `GOOGLE_API_K***` | 2026-04-15 |
| `badrshs/scribe-ai` | `tests/Feature/OpenAiIntegrationTest...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-15 |
| `badrshs/scribe-ai` | `tests/Feature/InstallCommandTest.ph...` | `sk-proj-env-env-var` | `OPENAI_API_K***` | 2026-04-15 |
| `affaan-m/agentshield` | `tests/rules/secrets.test.ts` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-15 |
| `affaan-m/agentshield` | `src/corpus/vulnerable-configs.ts` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-15 |
| `affaan-m/agentshield` | `examples/vulnerable/CLAUDE.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-15 |
| `affaan-m/agentshield` | `dist/index.js` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-15 |
| `ankitrajmehta/desktop-automati...` | `README.md` | `sk-proj-py-google-env` | `GOOGLE_API_K***` | 2026-04-15 |
| `NemroNeno/LinkedIn_messaging_a...` | `op.py` | `sk-proj-py-sk-proj` | `sk-proj-PDH5***` | 2026-04-15 |
| `tenebris-io/peanuts-hackio-202...` | `setup/SETUP-new.md` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-04-15 |
| `tylerprogramming/ai` | `crewai_flow_single_llm/README.md` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-15 |
| `tylerprogramming/ai` | `autogen_agentbuilder/OAI_CONFIG_LIS...` | `sk-proj-json-sk-generic` | `sk-7sWCWPvca***` | 2026-04-15 |
| `whyashthakker/ai-agents` | `research_results_20250212_110656.js...` | `sk-proj-json-sk-proj` | `sk-proj-l4Fa***` | 2026-04-15 |
| `whyashthakker/ai-agents` | `agents/environment/aqi/main.py` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-15 |
| `Shrujal00/Cognivo` | `api/DEPLOYMENT_GUIDE.md` | `sk-proj-js-env-var` | `OPENAI_API_K***` | 2026-04-15 |
| `rangashivuputty-droid/Thinkspy...` | `script.js` | `sk-proj-js-sk-proj` | `sk-proj-_kdd***` | 2026-04-15 |
| `MechanizedIT/inkspark` | `.env.tpl` | `sk-proj-env-sk-proj` | `sk-proj-zxUV***` | 2026-04-15 |
| `eudespankilhas/audiopankprodut...` | `.env.rtf` | `sk-proj-env-sk-proj` | `sk-proj-bRBw***` | 2026-04-15 |
| `macho715/cursor-mcp` | `.env.txt` | `sk-proj-env-sk-proj` | `sk-proj-BaHy***` | 2026-04-15 |
| `Nizar541/nizargpt4` | `.env.txt` | `sk-proj-env-sk-proj` | `sk-proj-6BL0***` | 2026-04-15 |
| `youask-oman/uaskstudents` | `.env,example.txt` | `sk-proj-env-sk-proj` | `sk-proj-GZ5t***` | 2026-04-15 |
| `Harishethi/ai-resume-analyzing` | `.env.py` | `sk-proj-env-sk-proj` | `sk-proj-QZCu***` | 2026-04-15 |
| `mwa-codes/coalqpdf` | `backend/.env.bak` | `sk-proj-env-sk-proj` | `sk-proj-_OYy***` | 2026-04-15 |
| `VivekDagur/AquaMind-Water-Mana...` | `backend/.env.env` | `sk-proj-env-sk-proj` | `sk-proj-DLr0***` | 2026-04-15 |
| `eudespankilhas/2025agenteia` | `.env.local.txt` | `sk-proj-env-sk-proj` | `sk-proj-bRBw***` | 2026-04-15 |
| `Wisekin/sikry-25` | `.env.local.txt` | `sk-proj-env-sk-proj` | `sk-proj-n6AI***` | 2026-04-15 |
| `spam108/telegram-warmup-bot` | `.env.backup.local` | `sk-proj-env-sk-proj` | `sk-proj--XEG***` | 2026-04-15 |
| `Thampson29/Rightly-App` | `rightly-app/backend/backend.env.txt` | `sk-proj-env-sk-proj` | `sk-proj-Zvsy***` | 2026-04-15 |
| `kemcell/chat-mysql` | `openapikey.env.txt` | `sk-proj-env-sk-proj` | `sk-proj-YpTR***` | 2026-04-15 |
| `eudespankilhas/social-genius-i...` | `.env.local.txt` | `sk-proj-env-sk-proj` | `sk-proj-MI_7***` | 2026-04-15 |
| `mkyoung23/RealRefiLoanAutomati...` | `.env.txt` | `sk-proj-env-sk-proj` | `sk-proj-TgG0***` | 2026-04-15 |
| `faysal-MMII/Tafseer` | `.env.save` | `sk-proj-env-sk-proj` | `sk-proj--ddn***` | 2026-04-15 |
| `rangashivuputty-droid/Thinkspy...` | `script.js` | `sk-proj-js-sk-proj` | `sk-proj-_kdd***` | 2026-04-15 |
| `NemroNeno/LinkedIn_messaging_a...` | `op.py` | `sk-proj-py-sk-proj` | `sk-proj-PDH5***` | 2026-04-15 |


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
