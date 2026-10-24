# Deterministic risk scoring

The baseline adds fixed heuristic points for configured indicators and caps the
result at 100. It is a severity/triage score, **not** a probability, model
confidence, or proof of fraud. Categories are:

| Score | Risk level | Meaning |
|---:|---|---|
| 0–29 | Low | Few or no configured indicators matched; this does not establish safety. |
| 30–59 | Medium | Multiple or higher-weight indicators warrant independent verification. |
| 60–100 | High | Several strong indicators matched; pause and do not follow the request without verification. |

## Message rules

- Urgency/account pressure: 20 points; additional distinct urgency phrases add
  5 each, capped at 30.
- Sensitive-information or unusual-payment terms: 20 points; additional
  distinct terms add 5 each, capped at 30.
- Prize, giveaway, or lottery language: 25 points.
- Organization/support impersonation phrasing: 15 points.
- A credential disclosure request: an additional 25 points when a password,
  passcode, PIN, or OTP is paired with a request to send, share, reply, enter,
  or provide it.
- A suspicious link contributes up to 30 points using the URL rules below.

## URL rules

- Embedded user information: 35 points.
- IP-address hostname: 25 points.
- Recognized URL shortener: 25 points.
- Punycode hostname: 25 points; other non-ASCII hostname: 20 points.
- Five or more hostname labels: 15 points.
- Three or more hyphens in the hostname: 10 points.
- URL longer than 120 characters: 10 points.
- HTTP rather than HTTPS: 8 points. HTTPS is not itself a trust signal.
- Missing or unspecified URL schemes do not incur HTTP-only points; an
  omitted scheme is not treated as proof that a connection uses HTTP.

## Email rules

Email applies relevant message and URL checks, then adds indicators for a
missing supplied `From` header (10 points), a Reply-To/sender domain mismatch
(25), an urgent subject (20), unusual sender format (10), and a sender/link
hostname difference (10). Domain differences and other indicators can be
legitimate; the results say so and do not claim sender authentication.

This simple additive model can double-count related signals and has not been
calibrated against a real labeled dataset. Do not use it for automated blocking
or as a substitute for security review. Changing thresholds or weights should
be accompanied by tests and documented evaluation.
