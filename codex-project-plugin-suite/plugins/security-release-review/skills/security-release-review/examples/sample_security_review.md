# Security Release Review — Example

Project: fan-community-demo  
Scope: local repository review  
Verdict: `BLOCK`

## Top Release Blockers

| Severity | Category | Finding | Evidence | Required Fix |
|---|---|---|---|---|
| BLOCKER | SMS/OTP | Public OTP endpoint has no IP/phone/device/global rate limit | `api/send-otp.ts` | Add rate limits, cooldown, budget alerts, CAPTCHA/risk challenge |
| BLOCKER | Upload | Uploaded images receive permanent public URLs with no moderation | `api/upload.ts` | Private bucket + signed URL + content review + size/type/magic bytes checks |
| HIGH | AI Chat | System prompt is sent to browser and no output moderation exists | `components/Chat.tsx` | Move prompt/key server-side; add input/output moderation and prompt-injection tests |

## Surface Map

| Surface | Files | Trust Boundary | Abuse Case | Existing Control | Gap |
|---|---|---|---|---|---|
| OTP | `api/send-otp.ts` | Anonymous -> SMS provider | SMS bombing/cost attack | phone required | no rate limit/budget |
| Comments | `api/comments.ts` | user -> public page | spam/illegal links | length check | no moderation/takedown |
| Upload | `api/upload.ts` | user file -> public CDN | public image host | extension check | no private storage/moderation |
| AI Chat | `components/Chat.tsx`, `api/chat.ts` | user prompt -> model | prompt leak/cost attack | basic prompt | no server-side safety |

## Bad Actor Questions

- Can SMS be abused? Yes. No per-IP/phone limit or provider budget alert was found.
- Can UGC be used for ads? Yes. Comments are immediately visible and links are allowed.
- Can upload become public file host? Yes. Permanent public URLs are returned.
- Can AI leak rules? Likely. System prompt is visible client-side.
- Can admins respond? Not enough evidence of takedown/ban/audit tools.

## Required Fixes Before Public Launch

- [ ] Add OTP rate limits: IP + phone + account/session + global budget.
- [ ] Make uploads private by default; issue short-lived signed URLs.
- [ ] Add upload size/type/magic bytes checks and image moderation queue.
- [ ] Put AI prompt/key on server; add input/output moderation and cost limits.
- [ ] Add comment moderation state and admin takedown.
