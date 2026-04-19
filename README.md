# 🔍 Codex API Key Exposure Monitor

> **SECURITY RESEARCH PROJECT**: Automated monitoring of publicly exposed Codex API keys on GitHub

⚠️ **IMPORTANT**: This project is for **security research and awareness purposes only**.
- No actual API keys are stored or logged
- Only publicly visible metadata is collected
- Repository owners are encouraged to revoke exposed keys immediately

---

## 📊 Latest Scan Results

**Last Updated**: 2026-04-19 16:47:10 UTC
**API Requests Made**: 10
**Total Unique Findings**: 220

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Key Types Detected** | 30 |
| **Affected Repositories** | 41 |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
| `sk-proj-json-sk-generic` | 47 |
| `sk-proj-json-env-var` | 37 |
| `sk-proj-json-anthropic-env` | 18 |
| `sk-proj-env-sk-proj` | 16 |
| `sk-proj-json-gemini-env` | 12 |
| `sk-proj-ts-anthropic-env` | 12 |
| `sk-proj-ts-env-var` | 10 |
| `sk-proj-json-google-env` | 7 |
| `sk-proj-py-sk-generic` | 7 |
| `sk-proj-json-claude-env` | 6 |
| `sk-proj-json-sk-proj` | 5 |
| `sk-proj-yml-env-var` | 5 |
| `sk-proj-json-groq-env` | 5 |
| `sk-proj-json-deepseek-env` | 5 |
| `sk-proj-py-env-var` | 3 |
| `sk-proj-yml-sk-generic` | 3 |
| `sk-proj-yml-sk-proj` | 3 |
| `sk-proj-json-embedding-env` | 3 |
| `sk-proj-py-sk-proj` | 2 |
| `sk-proj-js-sk-proj` | 2 |
| `sk-proj-env-env-var` | 2 |
| `sk-proj-py-anthropic-env` | 2 |
| `sk-proj-js-env-var` | 1 |
| `sk-proj-py-google-env` | 1 |
| `sk-proj-yml-google-env` | 1 |
| `sk-proj-json-llm-env` | 1 |
| `sk-proj-json-ai-env` | 1 |
| `sk-proj-ts-google-env` | 1 |
| `sk-proj-ts-llm-env` | 1 |
| `sk-proj-js-anthropic-env` | 1 |

### Recent Findings (Last 30 Days)

| Repository | File Path | Key Type | Preview | Discovered |
|------------|-----------|----------|---------|------------|
| `pdrago97/chat-w-ontology` | `.env.example` | `sk-proj-js-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-19 |
| `elizaOS/eliza` | `packages/examples/trader/README.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-18 |
| `elizaOS/eliza` | `packages/examples/supabase/env.exam...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-18 |
| `elizaOS/eliza` | `packages/examples/moltbook/env.exam...` | `sk-proj-ts-llm-env` | `LLM_API_KEY=***` | 2026-04-18 |
| `elizaOS/eliza` | `packages/examples/gcp/env.example` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-18 |
| `elizaOS/eliza` | `packages/examples/discord/env.examp...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-18 |
| `elizaOS/eliza` | `packages/examples/bluesky/env.examp...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-18 |
| `elizaOS/eliza` | `packages/docs/quickstart.mdx` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-18 |
| `elizaOS/eliza` | `packages/docs/guides/create-a-plugi...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-18 |
| `elizaOS/eliza` | `packages/benchmarks/OSWorld/mm_agen...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-18 |
| `promptfoo/promptfoo` | `site/docs/usage/self-hosting.md` | `sk-proj-ts-google-env` | `GOOGLE_API_K***` | 2026-04-18 |
| `promptfoo/promptfoo` | `site/docs/red-team/foundation-model...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-18 |
| `promptfoo/promptfoo` | `site/docs/guides/evaluate-langgraph...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-18 |
| `promptfoo/promptfoo` | `site/blog/red-team-claude.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-18 |
| `promptfoo/promptfoo` | `examples/redteam-mcp/README.md` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-18 |
| `promptfoo/promptfoo` | `examples/redteam-mcp-agent/README.m...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-18 |
| `promptfoo/promptfoo` | `examples/redteam-foundation-model/R...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-18 |
| `promptfoo/promptfoo` | `examples/integration-pydantic-ai/RE...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-18 |
| `promptfoo/promptfoo` | `examples/integration-helicone/READM...` | `sk-proj-ts-env-var` | `OPENAI_API_K***` | 2026-04-18 |
| `promptfoo/promptfoo` | `examples/config-node-package/README...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-18 |
| `promptfoo/promptfoo` | `examples/config-node-package-typesc...` | `sk-proj-ts-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-18 |
| `jaschadub/VectorSmuggle` | `docs/guides/vector_payload_dissocia...` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-04-17 |
| `jaschadub/VectorSmuggle` | `docs/guides/quick_start.md` | `sk-proj-py-env-var` | `OPENAI_API_K***` | 2026-04-17 |
| `jaschadub/VectorSmuggle` | `.env.example` | `sk-proj-py-sk-generic` | `sk-xxxxxxxxx***` | 2026-04-17 |
| `Coff0xc/Github-API-scan` | `test_ai_detector.py` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-17 |
| `Coff0xc/Github-API-scan` | `ai_detector.py` | `sk-proj-py-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-17 |
| `gaocaipeng/InCloudGitHub` | `scan_reports/scan_report_20251017_0...` | `sk-proj-py-sk-generic` | `sk-ayYLsHAhr***` | 2026-04-17 |
| `gaocaipeng/InCloudGitHub` | `scan_reports/scan_report_20251017_0...` | `sk-proj-py-sk-generic` | `sk-ayYLsHAhr***` | 2026-04-17 |
| `gaocaipeng/InCloudGitHub` | `scan_reports/scan_report_20251016_0...` | `sk-proj-py-sk-generic` | `sk-KKaB5nstn***` | 2026-04-17 |
| `gaocaipeng/InCloudGitHub` | `scan_reports/scan_report_20251016_0...` | `sk-proj-py-sk-generic` | `sk-w5QJTwntn***` | 2026-04-17 |
| `gaocaipeng/InCloudGitHub` | `scan_reports/scan_report_20251016_0...` | `sk-proj-py-sk-generic` | `sk-JQmEuwsfq***` | 2026-04-17 |
| `gaocaipeng/InCloudGitHub` | `scan_reports/scan_report_20251010_0...` | `sk-proj-py-sk-generic` | `sk-iVZ3N2WBX***` | 2026-04-17 |
| `ArgentAIOS/argentos-core` | `src/utils/redact.adversarial.test.t...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `johnson7788/MultiUserClaw` | `openclaw/src/infra/dotenv.test.ts` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/zhuangclaw/qst-memory/data/q...` | `sk-proj-json-sk-generic` | `sk-0FuMzdToH***` | 2026-04-16 |
| `openclaw/skills` | `skills/zhuangclaw/qst-memory-v1-8-5...` | `sk-proj-json-sk-generic` | `sk-0FuMzdToH***` | 2026-04-16 |
| `openclaw/skills` | `skills/zhuangclaw/q-memory/data/qst...` | `sk-proj-json-sk-generic` | `sk-0FuMzdToH***` | 2026-04-16 |
| `openclaw/skills` | `skills/zhenstaff/swarm-orchestrator...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/zhenstaff/swarm-orchestrator...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/zhenstaff/banking-agent-os/S...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/zhenstaff/banking-agent-os/S...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/zhaog100/openclaw-voice-skil...` | `sk-proj-json-sk-generic` | `sk-mvntgiyda***` | 2026-04-16 |
| `openclaw/skills` | `skills/yunneetoichoi/asdsadasd/.env` | `sk-proj-json-sk-proj` | `sk-proj-Z-KB***` | 2026-04-16 |
| `openclaw/skills` | `skills/yidahis/douyin-upload/script...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/yidahis/douyin-upload/refere...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/yangbuyiya/yby6-video-parser...` | `sk-proj-json-sk-generic` | `sk-xxxxxxxxx***` | 2026-04-16 |
| `openclaw/skills` | `skills/yangbuyiya/yby6-video-parser...` | `sk-proj-json-sk-generic` | `sk-xxxxxxxxx***` | 2026-04-16 |
| `openclaw/skills` | `skills/yangbuyiya/yby6-video-parser...` | `sk-proj-json-sk-generic` | `sk-xxxxxxxxx***` | 2026-04-16 |
| `openclaw/skills` | `skills/xiaohuaishu/competitor-radar...` | `sk-proj-json-sk-generic` | `sk-RPBUoe2SH***` | 2026-04-16 |
| `openclaw/skills` | `skills/xiaohuaishu/competitor-radar...` | `sk-proj-json-sk-generic` | `sk-RPBUoe2SH***` | 2026-04-16 |
| `openclaw/skills` | `skills/xiaohuaishu/api-key-guardian...` | `sk-proj-json-sk-generic` | `sk-RPBUoe2SH***` | 2026-04-16 |
| `openclaw/skills` | `skills/wilsonliu95/openclaw-toolbox...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/wanwan2qq/mood-cli-release/s...` | `sk-proj-json-deepseek-env` | `DEEPSEEK_API***` | 2026-04-16 |
| `openclaw/skills` | `skills/wanwan2qq/mood-cli-release/R...` | `sk-proj-json-deepseek-env` | `DEEPSEEK_API***` | 2026-04-16 |
| `openclaw/skills` | `skills/vimvem/ict/sensitive_info_sc...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/unrealbnb/binance-coach/src/...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/truongvknnlthao-gif/ppt-gene...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/truongvknnlthao-gif/ppt-gene...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/truongvknnlthao-gif/ppt-gene...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/snail3d/voice-devotional/uni...` | `sk-proj-json-groq-env` | `GROQ_API_KEY***` | 2026-04-16 |
| `openclaw/skills` | `skills/snail3d/clawforgod/universal...` | `sk-proj-json-groq-env` | `GROQ_API_KEY***` | 2026-04-16 |
| `openclaw/skills` | `skills/snail3d/clawd/universal-voic...` | `sk-proj-json-groq-env` | `GROQ_API_KEY***` | 2026-04-16 |
| `openclaw/skills` | `skills/sendwealth/ai-company/exampl...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/seantjs/tradingagents-cn-ass...` | `sk-proj-json-deepseek-env` | `DEEPSEEK_API***` | 2026-04-16 |
| `openclaw/skills` | `skills/sang-su0916/gajago-sns/autor...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/sang-su0916/gajago-sns/SKILL...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/samj12/betbud-prediction-mar...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/runningz1/union-search-skill...` | `sk-proj-json-google-env` | `GOOGLE_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/robinzhang/tiktok-video-audi...` | `sk-proj-json-sk-generic` | `sk-0zy1YyzLa***` | 2026-04-16 |
| `openclaw/skills` | `skills/robinzhang/tiktok-video-audi...` | `sk-proj-json-sk-generic` | `sk-0zy1YyzLa***` | 2026-04-16 |
| `openclaw/skills` | `skills/rhanbourinajd/ai-video-gen/Q...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/rcholic/predicate-snapshot/R...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/pearl799/district9/SKILL.md` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/pearl799/district9/README.md` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/paolorollo/openclaw-sec/src/...` | `sk-proj-json-sk-generic` | `sk-xxxxxxxxx***` | 2026-04-16 |
| `openclaw/skills` | `skills/paolorollo/openclaw-sec/__te...` | `sk-proj-json-sk-generic` | `sk-123456789***` | 2026-04-16 |
| `openclaw/skills` | `skills/onlyloveher/ai-video-gen-cn/...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/numba1ne/nft-skill/env-examp...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/nighty35628/safe-share/scrip...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/nighty35628/safe-share/scrip...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/nighty35628/safe-share/refer...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/nicemaths123/social-monitor/...` | `sk-proj-json-claude-env` | `CLAUDE_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/nicemaths123/automation-cont...` | `sk-proj-json-claude-env` | `CLAUDE_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/nhype/generate-presentation/...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/neuralshift1/iblai-openclaw-...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/ncreighton/healthcare-chatbo...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/nasplycc/nasplycc-clawra-sel...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/nasplycc/nasplycc-clawra-sel...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/msonline1110/oc-smart-agent-...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/mmyg11/ai-video-gen-temp/QUI...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/maxzyma/ohmyopenclaw/guides/...` | `sk-proj-json-deepseek-env` | `DEEPSEEK_API***` | 2026-04-16 |
| `openclaw/skills` | `skills/matttgx/ai-video-gen-1-0-0/Q...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/mattjackson/claw-apply/SKILL...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/mattjackson/claw-apply/READM...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/mashirops/auto-memory-distil...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/lycohana/siliconflow-vision/...` | `sk-proj-json-sk-generic` | `sk-ghkgkwxvt***` | 2026-04-16 |
| `openclaw/skills` | `skills/lockdown56/openclaw-sec-plus...` | `sk-proj-json-sk-generic` | `sk-xxxxxxxxx***` | 2026-04-16 |
| `openclaw/skills` | `skills/lichq1337/phishguard/INSTALA...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/leohuang8688/google-baidu-se...` | `sk-proj-json-google-env` | `GOOGLE_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/leejoe411-creator/apex/scrip...` | `sk-proj-json-sk-proj` | `sk-proj-1Jau***` | 2026-04-16 |

*... and 120 more unique findings (see `data/` directory)*


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
