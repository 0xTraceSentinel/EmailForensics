# EmailForensics

An offline toolkit for analysing exported mailboxes (PST, MSG, EML, MBOX) to work out **where a company's key executive decisions were really made**. This is the "place of effective management" (POEM) test that decides corporate tax residence.

The tool doesn't give a verdict. It turns a pile of exported email into **evidence an analyst can review**:
- a timeline for each decision,
- who drafted and who directed,
- where each person was,
- and every finding linked back to its source message and hash.

> Background on the legal test and the investigative method: [`docs/methodology.md`](docs/methodology.md)

> Status: early design. Nothing below is implemented yet.

---

## Why exported files instead of a scraper

Forensic work is done on **exports**, not live mailboxes:

| Live scraping (IMAP / Graph as the user) | Working on exports |
|---|---|
| Changes the mailbox (read flags, access times, audit entries) | Evidence stays untouched; the tool only reads copies |
| Needs the user's credentials or broad API permissions | Collection is done separately by the organisation's admin or an eDiscovery tool |
| IMAP loses MAPI properties (draft creation times, `Thread-Index`, sent-on-behalf-of) | PST/MSG keep the full MAPI property set |
| Hard to show a court exactly what was collected | Each input file is hashed and every record traces back to it |

So the project **starts at the export**: Purview eDiscovery output, Google Vault exports, or PST/EML files supplied by a client.

A read-only collector (e.g. a Microsoft Graph export module) could be added later as a separate, optional component. It is not on the critical path.

---

## Why keywords alone aren't enough

Searching for "board", "resolution" or "approved" finds candidate messages, but it can't show *where* a decision was made. The approach here is built around a **decision register** instead:

1. The analyst lists the key decisions from the minutes: what was decided, the formal date, and the formal place.
2. The tool finds everything related to each decision: threads, attachments, calendar items.
3. Analyzers attach indicators to each item (who, when, where, drafted vs. approved).
4. The output is a **per-decision timeline and indicator matrix** that compares the formal record with the email record.

Keywords and phrase lists are one input to step 2 and to the language analyzer. They are not the whole method.

---

## Architecture

```
                 ┌───────────────────────────────────────────────┐
  PST / OST ─┐   │  ingest/      parse → normalise → hash         │
  MSG ───────┼──►│               (provenance on every record)     │
  EML / MBOX ┘   └───────────────────────┬───────────────────────┘
                                         ▼
                              ┌─────────────────────┐
  decisions.yaml ────────────►│case store (Postgres)│◄──── people.yaml
  (decision register)         └──────────┬──────────┘     (identities, home base)
                                         ▼
     ┌──────────────┬──────────────┬─────┴────────┬──────────────┬──────────────┐
     │ headers      │ threading    │ attachments  │ presence     │ language     │
     │ tz offsets,  │ Message-ID,  │ OOXML / PDF  │ travel, OOO, │ instruction  │
     │ client, IPs  │ Thread-Index │ XMP, e-sign  │ calendar tz  │ vs. approval │
     └──────────────┴──────────────┴──────┬───────┴──────────────┴──────────────┘
                                          ▼
                     ┌──────────────────────────────────────┐
                     │ timeline · network · gaps/backdating │
                     └──────────────────┬───────────────────┘
                                        ▼
                     per-decision report (HTML / CSV) + exhibits
```

### Modules

| Module | What it does |
|---|---|
| `ingest` | Reads PST/OST, MSG, EML and MBOX. Extracts headers, bodies, MAPI properties, folder paths and nested attachments. Hashes every source file and item. |
| `store` | PostgreSQL case database (one database per case): messages, people, attachments, events, indicators. Each row records its source file, its path inside that file, and its hash. |
| `headers` | `Date:` time zone offset, `Received:` chain, client IPs where present, `X-Mailer`/`User-Agent`, sent-on-behalf-of. |
| `threading` | Rebuilds threads from `Message-ID`/`In-Reply-To`/`References`. Decodes Outlook `Thread-Index` to recover thread start times and replies whose parent message is missing. |
| `attachments` | OOXML `core.xml`/`app.xml` (author, last modified by, company, template, created/modified), tracked-changes authors, PDF XMP (create date with offset, creator tool), DocuSign/Adobe Sign audit trails (signer IPs and times). Hashes each file to follow it across mailboxes. |
| `presence` | Extracts flights, hotels, ride receipts, out-of-office replies and calendar time zones into a presence calendar per person. |
| `language` | Configurable phrase lists plus classification of instructions vs. approvals ("go ahead" vs. "approved as tabled"). Flags candidate privileged messages for review. |
| `timeline` | One UTC timeline per decision, keeping each item's original offset, labelled by phase (idea → negotiation → agreement → formal approval → execution). |
| `network` | Who starts threads, who instructs whom, centrality, and offshore directors left off key threads. |
| `anomalies` | Volume gaps, missing thread parents, deleted items, documents created after their stated date (backdating). |
| `report` | HTML/CSV per decision: indicator matrix, timeline, and exhibits linked to source hashes. |

### Planned CLI

```bash
emailforensics init  case01/                         # create case folder + PostgreSQL database
emailforensics ingest case01/ exports/*.pst exports/*.eml
emailforensics people case01/ people.yaml            # identities, aliases, home base
emailforensics register case01/ decisions.yaml       # key decisions from minutes
emailforensics analyze case01/                       # run all analyzers
emailforensics timeline case01/ D1                   # one decision's timeline
emailforensics report case01/ --out report/
```

Example `decisions.yaml`:

```yaml
- id: D1
  title: Acquire Target Ltd for USD 40m
  formal_date: 2023-06-14
  formal_place: Dubai (board meeting)
  source: Minutes 2023-06-14, p.3
  search:
    terms: ["Target Ltd", "Project Falcon", "SPA"]
    window: [2023-03-01, 2023-07-31]
```

---

## Design principles

1. **Read-only on evidence.** Inputs are never changed. Hashes are checked on ingest and again before reporting.
2. **Provenance everywhere.** Every indicator traces back to a source file, an item path and a hash.
3. **UTC plus original offset.** Timestamps are normalised for sorting, but the original offset is kept because it is evidence in its own right.
4. **Deterministic and reproducible.** The same inputs and config give the same outputs. Tool version and settings are recorded in every report.
5. **Analyst in the loop.** The tool shows indicators and their caveats (VPN, wrong device clock, assistants). It never declares residence.
6. **Privacy by default.** Case data stays local. No cloud calls. Possibly-privileged items are flagged for review before analysis.

---

## Proposed stack

| Need | Option |
|---|---|
| Language | Python 3.11+ |
| PST/OST | `libpff` (`pypff` bindings); `readpst` (libpst) as a fallback converter |
| MSG | `extract-msg` |
| EML / MBOX | stdlib `email`, `mailbox` |
| OOXML metadata | stdlib `zipfile` + `xml.etree` |
| PDF metadata | `pikepdf` |
| Storage | PostgreSQL 16+ (run locally via Docker Compose): `JSONB` for variable headers and MAPI properties, `tsvector` full-text search on bodies, `pg_trgm` for fuzzy name/alias matching, roles for multi-analyst review |
| DB access | `psycopg` 3 + SQL migrations (e.g. `alembic`) |
| Analysis | `pandas`, `networkx` |
| CLI | `typer` or `click` |
| Reports | Jinja2 → static HTML |

---

## Roadmap

- [ ] **M1 – Ingest:** EML/MBOX → PostgreSQL with hashing and provenance
- [ ] **M2 – PST/MSG:** MAPI properties, folder paths, Recoverable Items
- [ ] **M3 – Headers + threading:** time zone offsets, client info, `Thread-Index` decoding
- [ ] **M4 – Attachments:** OOXML, PDF XMP, e-signature audit trail parsing
- [ ] **M5 – Decision register + timeline:** per-decision timelines and CSV export
- [ ] **M6 – Presence + language:** travel extraction, instruction/approval classification
- [ ] **M7 – Network + anomalies:** centrality, exclusion, gaps, backdating
- [ ] **M8 – Reporting:** HTML indicator matrix with exhibits

---

## Test data

Use public data only. Never commit real case data.
- **Enron email corpus** (CMU, MBOX/maildir) and the **EDRM Enron PST** set: real corporate decision-making, good for developing threading, network and language analysis.
- **Synthetic fixtures** under `tests/fixtures/`: hand-built EML/MSG/DOCX/PDF files with known offsets, authors and `Thread-Index` values, to test each analyzer exactly.

---

## Disclaimer

For research, education and supporting qualified professionals. This is not legal advice. Findings must be reviewed by a qualified forensic examiner and tax counsel. Only analyse data you are lawfully authorised to process.
