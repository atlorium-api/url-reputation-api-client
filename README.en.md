# URL reputation API — phishing, malware and unwanted software check

[Русский](README.md) · **English**

Ready-to-run examples for the **URL reputation check API** in six languages: **Python, TypeScript (Node.js), Go, Java, C#, PHP.**
Find out whether an address is flagged for **phishing**, **malware** or **unwanted software** — one link at a time, or a batch of up to 100 addresses per call.

Every example **runs out of the box — no signup, no key, no card.** A public demo key is baked in.

```bash
git clone https://github.com/atlorium-api/url-reputation-api-client
cd url-reputation-api-client/python && pip install -r requirements.txt && python main.py
```

> The demo key returns **mock verdicts**, not real reputation data. The branch is selected by domain, using the reserved `example.com` documentation zone — so both meaningful branches, "clean" and "threat", are reproducible in a test instead of showing up at random. Swap in a live key and the same code returns real verdicts.

---

## What it is for

Moderating links in classifieds, comments and chats. Checking addresses from inbound mail before anyone clicks them. Filtering links in user profiles and signatures. Auditing outbound links on your own site.

The point: the verdict arrives as **machine-readable JSON, before the link is followed**. The service does not load the page under check and opens no connections to it, so the check does not tip off the owner of a malicious site.

The examples do not just print JSON — they **apply** it. Each ships a `screenUserContent()` function that turns the verdicts of every link in a post into a decision: publish, send to a moderator, or reject. The rules differ by category: phishing and malware block publication outright, unwanted software goes to a human, and a row with no verdict is **not treated as safe** — it goes to a human too.

## Quick start

Try the API without cloning anything:

```bash
curl -H "Authorization: Bearer ak_sandbox_demo_mockdata_v1" \
     "https://atlorium.com/api/urlcheck?url=https://phishing.example.com/login"
```

| Language | Run | Requires |
|----------|-----|----------|
| [Python](python/) | `pip install -r requirements.txt && python main.py` | Python 3.10+ |
| [TypeScript / Node.js](node/) | `npm install && npm start` | Node.js 20+ |
| [Go](go/) | `go run .` | Go 1.22+ |
| [Java](java/) | `java Main.java` | JDK 17+ (no dependencies) |
| [C#](csharp/) | `dotnet run` | .NET 8+ |
| [PHP](php/) | `php main.php` | PHP 8.1+ |

Pass your own links as arguments: `python main.py https://example.com https://danger.example.com/pay`

### Sandbox scenario domains

The demo key selects the response branch by the domain of the address under check. Matching is done on the host suffix, so subdomains work too.

| Address | What comes back |
|---------|-----------------|
| `malware.example.com` | `threat`, category `malware` |
| `phishing.example.com` | `threat`, category `social_engineering` |
| `unwanted.example.com` | `threat`, category `unwanted_software` |
| `danger.example.com` | `threat`, **two categories at once** — check that your parser reads the whole list, not just the first element |
| anything else | `clean` |

## Authentication

The key goes in the `Authorization` header:

```
Authorization: Bearer YOUR_KEY
```

| Key | Behaviour |
|-----|-----------|
| `ak_sandbox_demo_mockdata_v1` | **Demo key.** Public, shared by everyone. Returns mocks, charges nothing, needs no account. Responses are deterministic, so you can assert on them in tests. |
| Live key | Real reputation verdicts. Get one at [atlorium.com](https://atlorium.com) |

Switching to a live key requires **no code changes** — every example reads an environment variable:

```bash
export ATLORIUM_API_KEY="ak_your_live_key"
```

Every sandbox response carries the header `X-Atlorium-Sandbox: true`, so a mock can never be mistaken for a real verdict.

## Endpoints

Base URL: `https://atlorium.com`

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/urlcheck` | Verdict for a single link |
| `POST` | `/api/urlcheck/batch` | A batch of links in one call |

### `GET /api/urlcheck`

| Parameter | In | Type | Description |
|-----------|----|------|-------------|
| `url` | query | string | The address to check. The scheme may be omitted: `example.com/page` is normalised to `http://example.com/page`. Only `http` and `https` are accepted. The response returns the normalised form — that is exactly what was checked |

### `POST /api/urlcheck/batch`

The request body is an array of strings:

```json
[ "https://example.com", "http://phishing.example.com/login" ]
```

| Parameter | In | Type | Description |
|-----------|----|------|-------------|
| — | body | string[] | The list of addresses, **100** maximum. Empty strings and duplicates are dropped before the check: a duplicate adds no work and is not charged |

The order of results matches the order of the submitted links — match them by index.

## Response fields

### Single verdict

| Field | Type | Meaning |
|-------|------|---------|
| `url` | string | The normalised address — the one that was actually checked |
| `verdict` | string | **The key field.** `clean` — no record, `threat` — flagged, `unknown` — no verdict could be obtained |
| `threatTypes` | array | Threat categories: `malware`, `social_engineering`, `unwanted_software`. **This is a list** — one address can be flagged under several at once |
| `checkedAtUtc` | datetime | The moment of the check. Display it next to the verdict: it turns the claim into a dated one |
| `message` | string | Human-readable explanation |
| `elapsedMs` | number | Check duration, ms |

### Batch response

| Field | Type | Meaning |
|-------|------|---------|
| `results` | array | Verdicts in the order the links were submitted |
| `total` | number | How many links were checked |
| `threatCount` | number | How many were flagged |
| `unknownCount` | number | How many got no verdict. **Those rows are not charged** |
| `elapsedMs` | number | Duration of the whole check, ms |

## What "clean" means — and what the service does not do

This is the key caveat, and it is better read before the integration than after.

**`clean` means "at the moment of the check there is no threat record in the database", NOT "the site is safe".** A freshly registered phishing domain enters any reputation database in the world with a delay of hours: someone has to report it, or automation has to crawl it. That is why every response carries `checkedAtUtc` — display it next to the verdict. The examples build a separate branch on this: a "clean" verdict older than a day is flagged as needing a recheck before a long-lived publication.

**The service does not load the page under check**, does not resolve its name and opens no connections to it. Hence both the upside and the limitation: the check is invisible to the owner of a malicious site, but says nothing about the page content — only about the presence of a record in the database.

## Error handling

| Code | Cause | What to do |
|------|-------|------------|
| `400` | Link missing or malformed | An `http`/`https` address is required. In batch mode: the list is empty, holds only invalid addresses, or exceeds 100 rows |
| `401` | Key missing, expired or invalid | Check the `Authorization` header |
| `402` | Insufficient credit balance | Top up at [atlorium.com](https://atlorium.com) |
| `429` | Rate limit exceeded | Retry with backoff. **Cap your wait** — the server may honestly ask you to wait tens of minutes |
| `503` | No verdict could be obtained | Retry later. **You are not charged for our failures** |

All six examples map these codes to human-readable causes — see the `AtloriumError` class.

## Pricing

**Pay-as-you-go, no subscription.** One link is one unit of work; in batch mode there are as many units as links. Rows with no verdict (`verdict = unknown`) are **subtracted** from the charge: if three rows out of a hundred could not be checked, ninety-seven units are charged, not a hundred. A request in which no link could be checked is not charged at all.

Current prices: **[atlorium.com/pricing](https://atlorium.com/pricing)**

## Other Atlorium APIs

The same account and the same key also give you:

- [Image analysis](https://github.com/atlorium-api/image-moderation-api-client) — UGC moderation: content, objects and text ON the image
- [Email verification](https://github.com/atlorium-api/email-verification-api-client) — syntax, MX records, disposable addresses and spam traps
- [DNS lookup](https://github.com/atlorium-api/dns-lookup-api-client) — domain records, SPF and DMARC audit against spoofing
- [SSL certificate check](https://github.com/atlorium-api/ssl-certificate-check-api-client) — expiry, chain, monitoring
- [IP geolocation](https://github.com/atlorium-api/ip-geolocation-api-client) — geo, ASN, VPN, proxy and Tor detection
- [Site performance audit](https://github.com/atlorium-api/core-web-vitals-api-client) — Core Web Vitals and page load speed

Full catalogue: [atlorium.com](https://atlorium.com)

## Links

- **API reference (Swagger):** [atlorium.com/urlAPI](https://atlorium.com/urlAPI)
- **OpenAPI spec:** [urlcheck_en-US.json](https://atlorium.com/openapi/urlcheck_en-US.json)
- **Support:** support@atlorium.com

## License

[MIT](LICENSE)
