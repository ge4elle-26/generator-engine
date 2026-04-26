# Generator Engine — CLAUDE.md

## Build Status
V2.3 complete as of 2026-04-26.
All 16 original steps done.

Session 2 additional fixes:
- Memory pipeline — 8 broken points fixed (user-scoped paths, uid filtering, import proposal queue, approve flow, seed-memory auth, loadRelevantMemory includes user memories)
- Review tab — Firestore index 400 error fixed (JS filtering instead of field filter)
- Status strip — dot-only, model name text removed
- Keyboard scroll — visualViewport direct inline style, no CSS var delay
- Scope system — migrated from localStorage (ge_businesses, ge_custom_scopes) to Firestore at users/{uid}/config/businesses; GET /user-config and POST /user-config routes added
- Custom Scopes section — removed from State tab entirely (Businesses tab is source of truth)
- Businesses tab Chat button — working (applyScope + switchTab, scopeGrid reference removed from applyScope)
- Light mode theme — complete overhaul: token fixes, 30+ component overrides, applyTheme sets html background
- Behavior rules — 5 rules added to GE identity system prompt: Focus Lock, No Unsolicited Suggestions, Auto Response Calibration, Escalation Trigger, Time Awareness (client_timestamp + first-message greeting)

Next: Session 3 — To-do list, Reminders, Scheduling.

## Stack
- Frontend: Cloudflare Pages (generator-engine.pages.dev)
- Backend: Cloudflare Worker (ge-ai.grdrys26.workers.dev)
- Database: Firebase Firestore (generator-engine-ge-brain-mem)
- Auth: Firebase Auth (grdrys26@gmail.com)
- GitHub: ge4elle-26/generator-engine
- Local: C:\Users\EJ\Desktop\ge-runtime

## Rules — never break these
- Never include Firebase stub that sets window.firebase — blocks real init
- initFirebase() must run inside dynamic script loader completion callback
- Mobile layout: strictly 1-column no grid classes
- Never patch incrementally — audit all bugs first fix in one pass
- Never deliver without confirming: Firebase scripts present, auth listener present, login function intact, no duplicate initializations
- Never use hardcoded scope values — scopes come from localStorage ge_businesses
- Never break streaming — all model responses must stream via SSE
- Background is always 000000, cards always 1C1C1E, accent always 00FF87
- Models: gpt-5.4 for Think and logic, claude-sonnet-4-6 for default, gemini-2.5-flash for intent, claude-opus-4-6 for deep
- OpenRouter key is in Wrangler secret OPENROUTER_API_KEY — never hardcode it

## Before every build
1. Read this file
2. Audit current state fully
3. List all issues
4. Confirm list with Gerald
5. Fix everything in one pass

## Known mistakes to never repeat
- Placed Firebase SDK scripts between head and body — caused auth 400 errors
- Used capital L instead of lowercase l in apiKey — caused API_KEY_INVALID
- Hardcoded scope pills instead of making them dynamic
- Used gpt-4o instead of gpt-5.4
- Showed raw error text to frontend instead of controlled fallback message
