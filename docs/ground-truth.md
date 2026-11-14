# Ground-truth test mailbox

The report's claims about time zone offsets ("this writer emits +0000", "phones carry their local offset", "this sent item came from a phone") are only as good as their calibration. This protocol builds a small mailbox where the answer to every question is known, so the tool's rules can be measured instead of assumed. Run it once per email platform the case uses (for the real case: the company's Microsoft 365 tenant).

## 1. Accounts

Use test accounts on the same platforms as the case:

| Account | Why |
|---|---|
| Microsoft 365 / Exchange Online mailbox (same tenant type as the company) | The executive's own platform; decides how sent items and Date headers behave |
| Outlook.com / Hotmail | Consumer Microsoft path |
| Gmail | Common external counterpart |

One account receives everything (the "receiver"), so every test email exists both as a sent item and as a received copy with full headers.

## 2. Clients and devices

Send from each combination you can:

| Client | Device |
|---|---|
| Outlook desktop (Windows), Exchange account | laptop |
| Outlook desktop, IMAP/SMTP account (e.g. Gmail) | laptop |
| Outlook on the web | laptop browser |
| Outlook for iOS / Android | phone |
| Apple Mail on iPhone (Exchange account and Gmail account) | phone |
| Gmail web and Gmail app | laptop / phone |

## 3. Time zone settings

For each client, send once with each setting, and record it:

1. Device time zone **Africa/Johannesburg**, automatic time zone on.
2. Device time zone **Indian/Mauritius** (change the device setting; physical travel is not needed for the test).
3. Laptop only: time zone left on Johannesburg while the clock is set by hand to Mauritius time. This is the "wrong zone" case the clock check should catch.
4. Optional: Outlook on the web / Outlook.com account time zone set differently from the device.

## 4. Tagging

Put a unique tag in square brackets at the start of every subject: `[GT01] test`, `[GT02] test`, … Reply to a few of them from another client so the quoted-header method is exercised too (`[GT10] RE: …`).

Record each send in `truth.yaml` (see `docs/examples/truth.yaml`):

```yaml
tests:
  - tag: GT01
    client: Outlook desktop
    account: exchange
    device: desktop
    device_timezone: Africa/Johannesburg
    place: ZA
  - tag: GT02
    client: Apple Mail iPhone
    account: exchange
    device: phone
    device_timezone: Indian/Mauritius
    place: MU
```

`device` is one of `phone`, `tablet`, `desktop`, `web`. `device_timezone` is the IANA name set on the device; `place` is the place code you expect the tool to infer from the offset.

## 5. Export and run

Export both the sender's and the receiver's mailbox to PST the same way the case will be collected (Purview eDiscovery export for Microsoft 365), then:

```bash
emailforensics init cases/groundtruth
emailforensics ingest cases/groundtruth exports/sender.pst --custodian sender
emailforensics ingest cases/groundtruth exports/receiver.pst --custodian receiver
emailforensics people cases/groundtruth groundtruth-people.yaml
emailforensics analyze cases/groundtruth
emailforensics groundtruth cases/groundtruth truth.yaml --out groundtruth.csv
```

## 6. Reading the result

For each copy of each test email, `groundtruth.csv` shows:

- `offset` vs `expected_offset`: `offset_ok` is `yes` when the Date header carried the device's offset, `UTC` when it carried +0000 instead (the writer normalised it), `no` otherwise.
- `writer_device` vs `expected_device`: whether X-Mailer, signatures or property fingerprints identified the device correctly.
- `clock`: the clock check; test 3 above should show `whole_hours_off`.
- `place` vs `expected_place`.

The summary line `utc_by_client` lists which client/copy combinations wrote +0000. Those findings, with this CSV as the exhibit, are what the case report can cite when it says a given +0000 is uninformative. Keep the CSV, the truth file and the PST hashes with the case file.
