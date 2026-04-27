# Generator Engine — CLAUDE.md

## Build Status
V2.4 complete as of 2026-04-27.
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

Session 3 — Tasks/Reminders (2026-04-27):
- Firestore collection users/{uid}/todos — fields: title, scope, due_date, reminder_time, created_at, completed_at, status, user_id
- Worker routes: POST /todo (create), GET /todos (list with scope/status filter), POST /todo/complete (mark done)
- hasActionableContent() drives propose_todos flag in SSE done events (main + debate); suppressed in /think mode
- Tasks — 6th nav tab with scope filter pills, todo list, tap-to-complete animation
- "＋ Save as Task" chip after AI responses with action items; suggests title from first line of response
- FAB + bottom-sheet modal: title, scope, due date, reminder datetime-local inputs
- scheduleReminders() fires browser Notification at reminder_time for todos within 24h window
- Light mode overrides for all new task components; sessionId invariant fix (state events no longer overwrite sessionId)

Session 4 — Bug Fix Pass (2026-04-27):
- Bug 1 fixed: statusLabel (header) was showing "Runtime Connected" text — setRuntimeState now only updates the header dot (statusDot), not the text label. Dot-only as intended.
- Bug 2 fixed: actProposeMemory was calling POST /save (bypasses review queue). Added POST /memory route (handleCreateMemoryProposal) that writes to users/{uid}/memory_proposals for pending review. Added saveMemory() function in index.html. actProposeMemory now calls saveMemory(). handleRecallMemory now has try-catch around initFirestore + .catch(() => []) on db.query.
- Bug 3 fixed: handleReview had no try-catch around initFirestore — any Firestore init failure returned 500, triggering loadReview() catch block ("Could not load proposals."). Wrapped in try-catch; now returns { count:0, items:[] } on Firestore error instead of 500.

Session 7 — Format and icon fix (2026-04-27):
- Fix 1: Model icons were 404 — files had double extension (claude.png.png), renamed to claude.png/gpt.png/gemini.png; path in getModelIconPath() corrected to /public/icons/models/; onerror logging added to icon img
- Fix 2: Markdown removed — stripMarkdownForDisplay() added to worker.js, applied to fullText before done event and to each debate perspective; system prompt Formatting Rules block added forbidding asterisks, pound signs, bullet points, backticks; Think Mode and Execute Mode instructions updated to reinforce plain prose

Session 6 — Bug Fix Pass 2 (2026-04-27):
- Bug 1 fixed: worker handleChat crashed on empty message with attachment — changed !message guard to allow empty string when attachment_url or image present
- Bug 2 fixed: header dots removed — .hdr-dot, #statusDot, #activeModelDot hidden via CSS display:none!important (elements kept in DOM to avoid JS null crashes)
- Bug 3 fixed: Save to Memory / Dismiss buttons removed from all chat bubbles — save-row block deleted from renderMsg()
- Bug 4 fixed: scroll-to-bottom button added — .scroll-btn floats in chat area, shows when >80px from bottom, hides at bottom, onclick scrolls thread
- Bug 5 fixed: model icons wired — getModelIconPath() maps model string to /icons/models/claude.png, /icons/models/gpt.png, /icons/models/gemini.png; rendered as 16x16 icon after each AI bubble

Session 5 — Attachment System Phase 5.5 (2026-04-27):
- imageInput accept extended: image/*, PDF, text/*, .doc/.docx/.xlsx/.csv
- Images: existing base64 inline flow unchanged (imgBar preview)
- Non-images: fileAttach state, attachChip preview chip above composer, Storage upload on send
- uploadToStorage(): POST to Firebase Storage REST API using user ID token (not service account)
- Storage path: users/{uid}/attachments/{timestamp}_{filename}
- saveAttachmentMeta(): POST /attachment → Firestore users/{uid}/attachments
- attachment_url + attachment_name included in /chat body → AI receives [Attached file: name — url]
- renderMsg(): msg.attachment chip (.msg-attach-chip) below user bubble with tap-to-open link
- loadMemory(): Attachments section added (GET /attachments), filename + date + Open link
- worker.js: handleSaveAttachment (POST /attachment), handleListAttachments (GET /attachments)
- Both routes registered in router

Session 8 — Phase 2 Complete (2026-04-27):
- FIX 1: Enter-to-send desktop only (navigator.maxTouchPoints === 0)
- FIX 2: Header identity — hdrStatusText ("Live"/"Offline") + hdrHi ("Hi [name]") added to hdr-title; RUNTIME_STATES labels updated; setRuntimeState updates hdrStatusText; auth handler sets hdrHi from displayName or email prefix
- FIX 3: First-message greeting — TIME AWARENESS removes "Gerald" from chat greeting; rawTodosForBriefing added to second parallel fetch; open todos injected into system prompt on isFirstMessage
- FIX 4: Voice input — mic button added to input row; MediaRecorder → base64 → POST /transcribe → OpenRouter whisper-large-v3 → transcript in composer; recording state shown via .recording CSS class
- FIX 5: Offline queue — navigator.onLine check in send() for text-only messages; ge_offline_queue localStorage; queued messages show "Queued — sends when back online" label; window.addEventListener('online') drains queue automatically
- FIX 6: Push notifications — sw.js service worker; VAPID crypto helpers (webPushEncrypt, buildVapidJwt, sendWebPush) in worker.js; POST /push/subscribe saves subscriptions to Firestore; GET /push/vapid-public-key; GET /push/generate-keys (admin); scheduled() handler fires sendDailyBriefings at 7am/12pm/7pm Manila; wrangler.toml cron triggers added
- worker.js: handleTranscribe, handlePushSubscribe, handlePushVapidPublicKey, handleGeneratePushKeys, sendDailyBriefings added; all routes registered

Session 8 — Phase 1 Navigation Restructure (2026-04-27):
- Bottom nav collapsed to 3 tabs: Chat, Tasks, Review (Memory, State, Businesses removed from nav)
- Drawer restructured: Account section (email + Sign Out) at top; Briefcase scope switcher (businesses + Global, active scope highlighted) in middle; Memory, State, Import, Export, Research, Theme in lower section
- Header simplified: GE text + single runtime status dot (statusDot re-enabled, green=connected red=failed) + email + hamburger; themeBtn removed from header (kept hidden in DOM for JS); scope pill removed entirely
- renderDrawerScopes() and renderDrawerAccount() added; called from openDrawer() on every open
- scopeSelector hidden (display:none) — DOM kept for renderScopePills() internal use

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
