# Methodology: POEM Analysis from Email Evidence

How email evidence is used to work out **where a company's executive decisions are really made**. The usual case is a company incorporated in a low-tax or no-tax jurisdiction that may in fact be managed from South Africa.

> General information for learning and research. Not legal advice. Real matters need a South African tax attorney and a qualified forensic examiner.

---

## 1. The question being answered

Under the South African Income Tax Act (s1, definition of "resident"), a company incorporated outside SA is still SA tax resident if its **place of effective management (POEM)** is in SA. SARS Interpretation Note 6 (Issue 2) describes POEM as the place where the **key management and commercial decisions** needed for the business as a whole are **in substance** made.

So the investigation is not about where the board *says* it met. It asks:

> For each key decision, **who actually made it, when, and where were they at the time?**

Email is usually the best record of that. It shows ideas forming, being negotiated and being agreed, often weeks before a formal board meeting "approves" them.

Relevant case law on paper vs. reality:

| Case | Takeaway |
|---|---|
| *De Beers v Howe* (1906, UK) | Residence follows where "central management and control" actually is. |
| *Wood v Holden* (2006, UK) | An offshore board that genuinely considers and decides keeps residence offshore, even if it follows advice. |
| *Laerstate BV v HMRC* (2009, UK) | Where the director physically was when acting decided the outcome. |
| *Development Securities v HMRC* (CA, 2020, UK) | A Jersey board that just carried out the UK parent's instructions was UK resident. |
| *Oceanic Trust v CSARS* (2012, SA) | SA court discussing POEM. |

---

## 2. End-to-end process

```
 Scope ─► Preserve ─► Collect ─► Process ─► Decision register ─► Analyse ─► Weigh ─► Report
```

### 2.1 Scoping
- **Custodians:** formal directors (onshore and offshore), plus the people who may *really* decide: founder, CEO, CFO, parent-company executives, group legal, external advisors, executive assistants.
- **Period:** the tax years under review, plus a margin before and after.
- **Sources:** mailboxes (including Recoverable Items), archives, shared mailboxes, Teams chats and meeting records, OneDrive/SharePoint, calendars, e-signature platform records, and personal devices where lawfully obtained (WhatsApp is often where real decisions happen).

### 2.2 Preservation
- Place the custodians on **eDiscovery / litigation hold** (Microsoft Purview) or a **Google Vault hold** (Workspace). Deleted and edited items are then kept in Recoverable Items (`Deletions`, `Purges`, `Versions`, `DiscoveryHolds`).
- **Export logs now, before they expire.** Default retention is short:

| Log | Typical retention |
|---|---|
| Unified Audit Log (Audit Standard) | ~180 days |
| Unified Audit Log (Audit Premium) | 1 year (up to 10 with add-on) |
| Entra ID sign-in logs | 7 days (free) / 30 days (P1/P2) |
| Exchange message trace | 90 days |

  For historical tax years these logs are usually **gone**, unless the company sent them to a SIEM. The **content and metadata of the messages themselves** are what survive, and that's why this README focuses on them.

### 2.3 Collection
- Server-side export through Purview eDiscovery (Premium) or a forensic tool using the Microsoft Graph API (e.g. Nuix, Oxygen, Magnet AXIOM). **Never** log in as the user or export from their Outlook. That changes metadata and weakens the evidence.
- Export in native formats (PST / MSG / EML) so the **full transport headers and MAPI properties** are kept.
- Hash every export (SHA-256), record who did what and when, and keep the export manifests (chain of custody).
- Example Purview (KQL) search to target decision traffic:
  ```
  participants:"cfo@group.co.za" AND kind:email
  AND (subject:"resolution" OR subject:"board" OR "term sheet" OR "approval")
  AND sent>=2023-03-01 AND sent<=2024-02-29
  ```
- Where audit data still exists:
  ```powershell
  Search-UnifiedAuditLog -StartDate 2024-01-01 -EndDate 2024-03-31 `
    -UserIds director@offshoreco.ae -Operations Send,MailItemsAccessed,FileModified `
    -ResultSize 5000
  ```

### 2.4 Processing
1. **De-duplicate** by `Message-ID` and content hash. Keep a record of *which custodian held which copy*: who had a document is itself evidence.
2. **Normalise all timestamps to UTC, but keep the original offsets.** The offset is evidence (see §3.1).
3. **Rebuild threads** using `Message-ID`, `In-Reply-To`, `References` and Outlook's `Thread-Index` (§3.1).
4. **Extract attachments recursively** (zips, embedded documents, attachments inside attachments), hash them, and keep the email-to-attachment links.
5. **OCR** scanned PDFs, such as signed resolutions.
6. **Resolve identities:** map aliases, personal addresses, assistants and shared mailboxes to real people.
7. **Tag each person with a "base"** (SA, offshore, other) from employment records, so every message can later be classified by where its sender and recipients were.

### 2.5 Decision register
Before searching email, build a list of **key decisions** from the formal record:

| # | Decision | Formal date | Formal place | Source |
|---|---|---|---|---|
| D1 | Acquire Target Ltd for USD 40m | 2023-06-14 | Dubai board meeting | Minutes p.3 |
| D2 | USD 25m facility with Bank X | 2023-09-02 | Written resolution, Dubai | Resolution #7 |
| D3 | Declare dividend | 2024-02-20 | Dubai board meeting | Minutes p.1 |

Each decision becomes a **case file**, and the email analysis below fills it in.

---

## 3. Email analysis techniques

### 3.1 Header and MAPI metadata: where and when was each message created?

| Field | What it can show | Caveats |
|---|---|---|
| `Date:` header offset (`+0200` SAST vs `+0400` Gulf) | Time zone setting of the sending device | Laptops are often set to the wrong time zone; travel changes it. |
| `Received:` chain | Server path and transit times | Exchange Online usually hides the client IP; the hops are mostly Microsoft servers. |
| `X-Originating-IP` / `X-MS-Exchange-Organization-OriginalClientIPAddress` | Client IP when present | Often missing or internal-only; VPNs hide real location. |
| `X-Mailer` / `User-Agent` | Device or client (iPhone Mail, Outlook for Android, OWA) | Links messages to a specific person's device. |
| `Message-ID` domain/format | Originating system or device type | Format differs by client. |
| `Thread-Index` (Outlook) | The first 22 bytes encode the **thread start time** and a GUID; each reply adds a 5-byte time-delta block | Shows when and how a thread started **even if earlier messages were deleted**. |
| `PR_CLIENT_SUBMIT_TIME` / `PR_MESSAGE_DELIVERY_TIME` | Send vs. delivery time | Big gaps can mean the device was offline or sent from a queue. |
| `PR_CREATION_TIME` / `PR_LAST_MODIFICATION_TIME` on drafts | When a draft resolution or email was first written and last edited | Very strong for "drafted before the meeting". |
| `PR_LAST_MODIFIER_NAME` | Who last changed an item | Useful in shared and delegated mailboxes. |
| Sent-on-behalf-of / `Sender:` vs `From:` | An assistant sending for a director | Separates who decided from who typed it. |

### 3.2 Decision timeline: did the decision come before the meeting?
For each decision in the register, place every related message, attachment, chat and calendar item on one UTC timeline and label the phases:

```
 First idea ─► Analysis ─► Negotiation ─► Agreement ─► "Board approval" ─► Execution
   (who/where)  (who/where)  (who/where)   (who/where)   (formal place)     (who/where)
```

Typical findings that point to SA management:
- The deal is agreed by SA executives ("we're going ahead, tell the bank") **before** the offshore meeting.
- The board pack is sent to offshore directors hours before the meeting with "please approve".
- The minutes are drafted in SA, sometimes **before** the meeting date.
- Execution emails to banks and counterparties come from SA people, citing a resolution that already "exists".

The opposite pattern supports offshore management: offshore directors ask questions, push back, change terms, or reject proposals, and the outcome changes as a result.

### 3.3 Who directs whom
Run network analysis across the collection:
- Who sends **instructions** and who sends **confirmations**? Classify messages by speech act ("please sign", "approved", "I've decided", "for your information").
- Count **who starts threads** about each decision and who has the **last substantive word**.
- Measure **centrality:** if the SA CFO connects bankers, lawyers and the offshore board, while the offshore directors only reply to the CFO, the decision-making centre is the CFO.
- Note **exclusion:** substantive discussions the offshore directors were never copied on.

### 3.4 Language and content
Concept and keyword searches, followed by human review, for phrases that show decisions already made or rubber-stamping:
- "as discussed in Joburg / at the Sandton meeting", "we've decided", "the board just needs to sign off", "formality", "for the file", "backdate", "make sure it's signed in Dubai", "don't email the offshore directors about this", "for tax reasons the meeting must be held in…"
- Advisors' warnings about POEM, then later emails that ignore them (shows awareness).
- Remember that legal advice may be privileged: **run a privilege review before analysis** (TAA s42A procedure in SA).

### 3.5 Attachment and document metadata
Attachments often say more than the emails carrying them.

| Artifact | Where | What it shows |
|---|---|---|
| DOCX/XLSX `docProps/core.xml` | `dc:creator`, `cp:lastModifiedBy`, `dcterms:created`, `dcterms:modified` (UTC) | Who drafted the "offshore" resolution and when |
| DOCX `docProps/app.xml` | `Company`, `Template`, `TotalTime`, `Application` | The SA group's template or licence inside an "offshore" document |
| Track changes / comments | `word/document.xml`, `word/comments.xml` | Names and timestamps of every editor |
| PDF XMP | `xmp:CreateDate` (often **with local offset**), `CreatorTool`, `Producer` | Where and when the PDF was produced (e.g. scanner in the SA office) |
| E-signature audit trail (DocuSign certificate of completion, Adobe Sign audit report) | Per signer: email, **IP address**, timestamps, view and sign events | Where each director **actually** was when signing. Often the best location evidence available. |
| SharePoint/OneDrive version history | Each saved version with editor and time | Shows the drafting process across people |

**Hash every attachment** and follow the same file across mailboxes. That shows who had the final version first, and whether the offshore board received a finished document rather than taking part in drafting.

### 3.6 Evidence of physical presence found in the mailbox
Mailboxes contain many records of where people were. Extract them into a **presence calendar** per decision-maker:
- Flight and hotel confirmations, boarding passes, visa emails.
- Ride-hailing and restaurant receipts (they include city and time).
- Out-of-office replies ("in Dubai until 16 June").
- Expense system notifications, corporate card alerts.
- Calendar items: organiser, attendees, location, **and the time zone stored with the appointment**, which reflects the organiser's device setting.
- Teams meeting records: who joined, for how long, and (if logs exist) from which IP.

Then compare: **Formal place of the meeting** vs **where each director actually was** vs **where the people who did the real work were**.

### 3.7 Gaps, deletions and backdating
- **Volume gaps:** missing periods around key decisions in one custodian's mailbox but not in counterparties' mailboxes.
- **Recoverable Items / Purges:** items deleted shortly before or after the investigation started.
- **Thread-Index orphans:** replies whose thread start points to a message that no longer exists.
- **Backdating:** minutes or resolutions whose document creation time is **after** the date they state, or whose earliest email circulation comes after their stated date.
- **Channel shift:** "let's take this offline / to WhatsApp" just before decisions go quiet in email. This points to sources that need separate collection.

---

## 4. Weighing the evidence

No single artifact decides POEM. Score each decision across independent indicators:

| Indicator | D1 | D2 | D3 |
|---|---|---|---|
| Decision substantively agreed before formal approval (timeline) | SA | SA | Offshore |
| Who initiated and directed (network/speech acts) | SA | SA | Mixed |
| Who drafted the approving documents (metadata) | SA | SA | Offshore |
| Where signers physically were (e-sign trail, presence calendar) | Offshore | SA | Offshore |
| Offshore board's real input (questions, changes, rejections) | None | None | Some |
| **Overall** | **SA** | **SA** | **Offshore** |

Rule out alternative explanations before drawing conclusions:
- VPN or roaming IPs.
- Wrong device time zones.
- Assistants sending on behalf of directors.
- Shared mailboxes.
- Legitimate advisory input, which can be offshore-compliant (*Wood v Holden*).

The test is about substance: getting advice from SA is not the same as the decision being made in SA.

---

## 5. Reporting

- Expert report structured per decision, with an exhibit for every finding (message, header extract, metadata dump, hash).
- Fully **reproducible:** tool versions, search terms, processing settings and hash lists, so the other side's expert can verify every step.
- State limitations clearly: expired logs, uncollected personal devices, privileged material withheld.

---

## 6. Related legal context (SA)

- **SARS information powers:** Tax Administration Act s46 (request for information, including material in the taxpayer's "possession or control", which covers its own cloud tenant), s48–s50 (audit, inquiry), s59–s63 (search and seizure).
- **Cross-border information:** exchange-of-information articles in double tax agreements, Tax Information Exchange Agreements with low-tax jurisdictions, and the multilateral Convention on Mutual Administrative Assistance in Tax Matters.
- **Treaty tie-breakers:** where the other country has a treaty with SA, residence may be decided by POEM or by agreement between the two tax authorities, depending on the treaty. True zero-tax jurisdictions usually have no treaty with SA, so the domestic POEM test applies on its own.
- **CFC rules (s9D):** even with POEM genuinely offshore, SA shareholders may be taxed on the company's income.

---

## 7. Defensive use

A company can run the same analysis on itself, before SARS does, to check that its email trail matches its minutes. Offshore decision-making that is real (offshore directors with authority, board packs prepared offshore, real discussion recorded in email) is what survives this kind of review.
