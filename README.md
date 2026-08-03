# Scam Shield — Backend (Module 1 + Module 2: Foundation & Authentication)

## Setup
```bash
cd backend
npm install
cp .env.example .env
# edit .env -> set MONGO_URI and JWT_SECRET
npm run dev
```

Server runs at `http://localhost:5000`.

## Endpoints
| Method | Route            | Auth | Description        |
|--------|-------------------|------|---------------------|
| GET    | /api/health       | No   | Health check        |
| POST   | /api/auth/register| No   | Create account       |
| POST   | /api/auth/login   | No   | Login, returns JWT   |
| GET    | /api/auth/me      | Yes  | Get logged-in user   |
| POST   | /api/auth/logout  | Yes  | Logout               |

Requires MongoDB running locally or a MongoDB Atlas URI in `.env`.

## Module 3 — Dashboard
New endpoints (all require `Authorization: Bearer <token>`):

| Method | Route                | Description                              |
|--------|----------------------|-------------------------------------------|
| GET    | /api/dashboard/stats | Total/Safe/Suspicious/Dangerous counts + tip of the day |
| GET    | /api/scans/latest    | Most recent scan (for "Recent Scan Result" panel) |
| GET    | /api/scans/recent    | Last N scans (`?limit=5`)                 |
| GET    | /api/scans           | Paginated scan history (`?page=&limit=&type=&verdict=`) |
| POST   | /api/scans           | Create a scan record (used by the scanner modules) |

### Demo data
To see the dashboard populated immediately after registering a user:
```bash
node seed.js you@example.com
```
This inserts 5 sample scans (SMS, Email, Website, QR, WhatsApp) matching the mockup.

## Module 4 — SMS Detection
| Method | Route            | Description                                         |
|--------|-------------------|------------------------------------------------------|
| POST   | /api/sms/analyze  | `{ message }` → runs rule-based scam analysis, saves a Scan, returns verdict/score/reasons |

`utils/scamAnalyzer.js` holds the scoring rules (prize claims, urgency language, shortened URLs, OTP/PIN requests, impersonation patterns, etc.) — each match adds weighted points, capped at 100. This same analyzer will be reused by Module 5 (Email Detection) with a couple of email-specific rules added.

## Module 5 — Email Detection
| Method | Route              | Description                                                        |
|--------|--------------------|----------------------------------------------------------------------|
| POST   | /api/email/analyze | `{ senderEmail, subject, body }` → runs `analyzeEmail`, saves a Scan, returns verdict/score/reasons |

`analyzeEmail` reuses all the SMS/text rules on `subject + body`, then layers on email-specific checks: lookalike/spoofed brand domains (e.g. `paypa1-verify.com`), a brand mentioned in the body but sent from a free email provider, and generic greetings ("Dear Customer").

## Module 6 — Website Analysis
| Method | Route                | Description                                              |
|--------|----------------------|------------------------------------------------------------|
| POST   | /api/website/analyze | `{ url }` → runs `analyzeWebsite`, saves a Scan, returns verdict/score/reasons |

`analyzeWebsite` checks: missing HTTPS, raw IP address instead of a domain, scam-associated TLDs (.xyz/.top/.club/etc.), excessive subdomains or hyphens, scam keywords in the URL (free/claim/verify/prize), lookalike brand domains, and known URL shorteners.

## Module 7 — QR Code Scanner
| Method | Route          | Description                                                        |
|--------|-----------------|----------------------------------------------------------------------|
| POST   | /api/qr/analyze | `{ qrData }` (already decoded on the client) → runs `analyzeWebsite` if it looks like a URL, otherwise `analyzeText`, saves a Scan |

QR image decoding happens entirely client-side (via `jsqr`) — the backend only ever sees the decoded text/URL, same as any other scan.

## Module 8 — Voice Scam Analyzer
| Method | Route            | Description                                                          |
|--------|-------------------|------------------------------------------------------------------------|
| POST   | /api/voice/analyze | `{ callerNumber, transcript }` → runs `analyzeVoice`, saves a Scan   |

`analyzeVoice` reuses the base text rules plus call-specific ones: government/police impersonation, robocall IVR patterns ("press 1"), requests to install remote-access software (AnyDesk/TeamViewer), gift-card/crypto/wire payment demands, "your child is in trouble" impersonation scams, account-suspension threats, and suspicious/hidden caller ID.

## Module 10 — Reports
| Method | Route                    | Description                                                       |
|--------|---------------------------|----------------------------------------------------------------------|
| GET    | /api/reports/summary?days=30 | Scans by type, by verdict, daily trend for the window, top 5 recurring scam patterns |
| GET    | /api/reports/export.csv  | Downloads the user's full scan history as CSV                     |

Both are aggregation queries scoped to `req.user._id` — no admin/cross-user data is ever exposed. This completes all 10 modules on the original plan.

## Bonus — Admin Panel
| Method | Route          | Description                                                    |
|--------|-----------------|------------------------------------------------------------------|
| GET    | /api/admin/users | Admin-only. Every registered user + their scan counts (total/safe/suspicious/dangerous) and last scan date |

Requires `role: "admin"` on the User document. To promote a user:
```bash
node makeAdmin.js you@example.com
```
Then log out and back in (or just refresh — `/auth/me` picks up the new role) and an "Admin Panel" link appears in the sidebar automatically.

## Bonus — PWA
The frontend now ships a `manifest.json` and a service worker (`public/service-worker.js`), so it's installable as an app from the browser (Chrome/Edge "Install" prompt, or "Add to Home Screen" on mobile). No backend changes needed for this — it's purely a frontend/browser feature. See the frontend README for details.
