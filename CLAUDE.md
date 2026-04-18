# Generator Engine — CLAUDE.md

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
