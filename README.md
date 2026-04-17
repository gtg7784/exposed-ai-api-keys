# 🔍 Codex API Key Exposure Monitor

> **SECURITY RESEARCH PROJECT**: Automated monitoring of publicly exposed Codex API keys on GitHub

⚠️ **IMPORTANT**: This project is for **security research and awareness purposes only**.
- No actual API keys are stored or logged
- Only publicly visible metadata is collected
- Repository owners are encouraged to revoke exposed keys immediately

---

## 📊 Latest Scan Results

**Last Updated**: 2026-04-17 10:26:08 UTC
**API Requests Made**: 10
**Total Unique Findings**: 188

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Key Types Detected** | 24 |
| **Affected Repositories** | 35 |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
| `sk-proj-json-sk-generic` | 47 |
| `sk-proj-json-env-var` | 37 |
| `sk-proj-json-anthropic-env` | 18 |
| `sk-proj-env-sk-proj` | 16 |
| `sk-proj-json-gemini-env` | 12 |
| `sk-proj-json-google-env` | 7 |
| `sk-proj-json-claude-env` | 6 |
| `sk-proj-json-sk-proj` | 5 |
| `sk-proj-yml-env-var` | 5 |
| `sk-proj-json-groq-env` | 5 |
| `sk-proj-json-deepseek-env` | 5 |
| `sk-proj-ts-anthropic-env` | 4 |
| `sk-proj-yml-sk-generic` | 3 |
| `sk-proj-yml-sk-proj` | 3 |
| `sk-proj-json-embedding-env` | 3 |
| `sk-proj-py-sk-proj` | 2 |
| `sk-proj-js-sk-proj` | 2 |
| `sk-proj-env-env-var` | 2 |
| `sk-proj-js-env-var` | 1 |
| `sk-proj-py-env-var` | 1 |
| `sk-proj-py-google-env` | 1 |
| `sk-proj-yml-google-env` | 1 |
| `sk-proj-json-llm-env` | 1 |
| `sk-proj-json-ai-env` | 1 |

### Recent Findings (Last 30 Days)

| Repository | File Path | Key Type | Preview | Discovered |
|------------|-----------|----------|---------|------------|
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
| `openclaw/skills` | `skills/leefj0606/sensitive-info-pro...` | `sk-proj-json-sk-generic` | `sk-123456789***` | 2026-04-16 |
| `openclaw/skills` | `skills/leefj0606/sensitive-info-pro...` | `sk-proj-json-sk-generic` | `sk-123456789***` | 2026-04-16 |
| `openclaw/skills` | `skills/kulotzkih/lex/scripts/init-a...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/kryptopaid/build-warden-agen...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/kern1x/ai-news-pusher/SKILL....` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/kaudata/diagramgenerator/REA...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/kaigegao1110/archive-project...` | `sk-proj-json-sk-generic` | `sk-123456789***` | 2026-04-16 |
| `openclaw/skills` | `skills/jeffli2002/jeffli-content-fa...` | `sk-proj-json-sk-generic` | `sk-abc123def***` | 2026-04-16 |
| `openclaw/skills` | `skills/jazzqi/memory-core-ng/test-r...` | `sk-proj-json-sk-generic` | `sk-BrwHc1Zia***` | 2026-04-16 |
| `openclaw/skills` | `skills/jazzqi/memory-core-ng/config...` | `sk-proj-json-sk-generic` | `sk-BrwHc1Zia***` | 2026-04-16 |
| `openclaw/skills` | `skills/jame-mei-ltp/sre-agent/docs/...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/jame-mei-ltp/aiops-agent/doc...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/itrocker/nanobanana-ppt-skil...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/itrocker/nanobanana-ppt-skil...` | `sk-proj-json-gemini-env` | `GEMINI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/itrocker/nanobanana-ppt-skil...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/hirofumiko/resume-ats/SKILL....` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/hirofumiko/code-review-autom...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/hhhh124hhhh/ai-video-gen-too...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/hexiaochun/pricing-test/scri...` | `sk-proj-json-sk-generic` | `sk-df83fa572***` | 2026-04-16 |
| `openclaw/skills` | `skills/gandli-2025/claw-compactor/t...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/g4dr/tiktok-trend-radar/SKIL...` | `sk-proj-json-claude-env` | `CLAUDE_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/g4dr/social-listening-monito...` | `sk-proj-json-claude-env` | `CLAUDE_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/g4dr/business-opportunity-de...` | `sk-proj-json-claude-env` | `CLAUDE_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/g4dr/auto-content-generator/...` | `sk-proj-json-claude-env` | `CLAUDE_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/evan-y25/twitter-dance/USAGE...` | `sk-proj-json-sk-generic` | `sk-JM5Ji1efm***` | 2026-04-16 |
| `openclaw/skills` | `skills/evan-y25/twitter-dance/READM...` | `sk-proj-json-sk-generic` | `sk-JM5Ji1efm***` | 2026-04-16 |
| `openclaw/skills` | `skills/evan-y25/twitter-dance/QUICK...` | `sk-proj-json-sk-generic` | `sk-JM5Ji1efm***` | 2026-04-16 |
| `openclaw/skills` | `skills/ernestyu/clawsqlite-knowledg...` | `sk-proj-json-embedding-env` | `EMBEDDING_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/eladrave/composiocli/rules/s...` | `sk-proj-json-env-var` | `OPENAI_API_K***` | 2026-04-16 |
| `openclaw/skills` | `skills/edwardirby/teams-anthropic-i...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/durtydhiana/pai/DEPLOYMENT.m...` | `sk-proj-json-anthropic-env` | `ANTHROPIC_AP***` | 2026-04-16 |
| `openclaw/skills` | `skills/dream458268696/openclaw-fall...` | `sk-proj-json-sk-generic` | `sk-6cbc43a72***` | 2026-04-16 |

*... and 88 more unique findings (see `data/` directory)*


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
