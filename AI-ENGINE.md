# AI Engine — Language Coverage

## Supported Languages

Both `INJECTION_PATTERNS` and `IDENTITY_LEAK_PATTERNS` are covered for all languages below.

| Language | Code | Status |
|----------|------|--------|
| English | EN | ✅ Original |
| Spanish | ES | ✅ Original |
| French | FR | ✅ Original |
| German | DE | ✅ Original |
| Italian | IT | ✅ Original |
| Portuguese | PT | ✅ Original |
| Russian | RU | ✅ Original |
| Chinese | ZH | ✅ Original |
| Arabic | AR | ✅ Added (#8) |
| Turkish | TR | ✅ Added (#8) |
| Korean | KO | ✅ Added (#8) |
| Japanese | JA | ✅ Added (#8) |
| Hindi | HI | ✅ Added (#8) |
| Persian/Farsi | FA | ✅ Added (#8) |
| Vietnamese | VI | ✅ Added (#8) |
| Polish | PL | ✅ Added (#8) |
| Dutch | NL | ✅ Added (#8) |
| Indonesian | ID | ✅ Added (#8) |
| Thai | TH | ✅ Added (#8) |
| Ukrainian | UK | ✅ Added (#8) |
| Romanian | RO | ✅ Added (#8) |

**Total: 21 languages**

## Notes

- SOV languages (TR, KO, JA, HI, FA) include verb-last pattern matching to
  catch natural attacker phrasing e.g. `tüm talimatları unut`
- Identity leak patterns require compound phrases to avoid false positives
  on common standalone words (e.g. Dutch `val`, Arabic `طعم`)
- All patterns use `\s+` instead of literal spaces for robustness
