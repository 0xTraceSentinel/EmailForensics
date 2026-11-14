from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass, field

from emailforensics.analysis import text

CLIENT_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"iphone mail|ios mail", re.I), "phone", "Apple Mail (iPhone)"),
    (re.compile(r"ipad mail", re.I), "tablet", "Apple Mail (iPad)"),
    (re.compile(r"outlook[- ]?(for )?(ios|iphone)", re.I), "phone", "Outlook for iOS"),
    (re.compile(r"outlook[- ]?(for )?android", re.I), "phone", "Outlook for Android"),
    (re.compile(r"\bandroid\b|samsung ?mail|blackberry|k-9 mail|nine - |aquamail|gmail ?(for )?android", re.I), "phone", None),
    (re.compile(r"apple mail|mac os x mail|macos mail", re.I), "desktop", "Apple Mail (Mac)"),
    (re.compile(r"microsoft (office )?outlook|outlook express|windows live mail|windows mail|microsoft-macoutlook", re.I), "desktop", "Outlook (desktop)"),
    (re.compile(r"thunderbird|icedove|seamonkey|postbox|em client|the bat|mailbird|evolution", re.I), "desktop", None),
    (re.compile(r"roundcube|zimbra|horde|squirrelmail|open-xchange|rainloop|owa|outlook web", re.I), "web", None),
    (re.compile(r"yahoomailweb|yahoo ?mail|aol webmail|webmail", re.I), "web", None),
]

PATH_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\.prod\.outlook\.com>?$", re.I), "microsoft_cloud", "service"),
    (re.compile(r"@(?:[\w-]+\.)*phx\.gbl>?$", re.I), "hotmail_legacy", "service"),
    (re.compile(r"@mail\.gmail\.com>?$", re.I), "gmail", "service"),
    (re.compile(r"@(?:[\w-]+\.)*mail\.(?:[\w-]+\.)*yahoo\.com>?$", re.I), "yahoo", "service"),
    (re.compile(r"^<?[0-9a-f]{12,16}\$[0-9a-f]{6,10}\$[0-9a-f]{6,10}\$@", re.I), "outlook_smtp", "client"),
    (re.compile(r"^<?[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}@"), "apple_client", "client"),
]

EXCHANGE_HEADERS = ("x-ms-tnef-correlator", "x-ms-exchange-messagesentrepresentingtype", "x-ms-exchange-organization-authas")


@dataclass
class Writer:
    device: str = "unknown"
    client: str | None = None
    path: str = "unknown"
    date_by: str = "unknown"
    basis: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.path}/{self.device}"

    def json(self) -> dict:
        return asdict(self)


def _header(headers: list[dict], name: str) -> str | None:
    low = name.lower()
    return next((h["value"].strip() for h in headers if h["name"].lower() == low and h["value"].strip()), None)


def classify(headers: list[dict], message_id: str | None, authored: str) -> Writer:
    w = Writer()
    agent = _header(headers, "X-Mailer") or _header(headers, "User-Agent")
    if agent:
        w.client = agent[:120]
        for rx, device, label in CLIENT_RULES:
            if rx.search(agent):
                w.device = device
                w.client = label or w.client
                w.basis.append(f"agent header: {agent[:80]}")
                break
    sig = text.mobile_signature(authored[-600:] if authored else "")
    if sig:
        sig_device = "tablet" if "ipad" in sig.lower() else "phone"
        if w.device == "unknown":
            w.device = sig_device
            w.basis.append(f"signature: {sig}")
        elif w.device != sig_device:
            w.basis.append(f"signature disagrees with agent: {sig}")
    if message_id:
        for rx, path, by in PATH_RULES:
            if rx.search(message_id):
                w.path, w.date_by = path, by
                w.basis.append(f"message-id pattern: {path}")
                break
    names = {h["name"].lower() for h in headers}
    if w.path == "unknown" and names & set(EXCHANGE_HEADERS):
        w.path, w.date_by = "exchange", "service"
        w.basis.append("exchange transport headers")
    if w.path == "unknown" and w.device in ("phone", "tablet", "desktop") and agent:
        w.date_by = "client"
        w.basis.append("client agent header without a service message-id")
    return w


FINGERPRINT_PROPS = (
    "0x3fde0003",
    "0x3ff10003",
    "0x3ffd0003",
)

VOLATILE = re.compile(
    r"attach|0x0e1b|0x0e08|0x0e07|0x0e17|0x1080|0x1081|0x1082|0x1090|0x1091|0x0017|0x0036|0x0026|0x0e2[0-9a-f]|"
    r"0x3fe[0-9a-f]|0x0e0[2-4]|reminder|flag|categor|0x8503|0x8506|0x8510|0x8514|0x8516|0x8517|0x8520|0x8530|0x8534|0x8535",
    re.I,
)


def fingerprint(props: dict | None, has_text: bool, has_html: bool, message_class: str | None) -> str | None:
    if not props:
        return None
    keys = sorted(k.lower() for k in props if not VOLATILE.search(k))
    values = [f"{k}={props[k].get('value')}" for k in FINGERPRINT_PROPS if k in props]
    raw = "|".join([message_class or "", f"text={has_text}", f"html={has_html}", *values, *keys])
    return hashlib.sha256(raw.encode()).hexdigest()


def label_clusters(groups: dict[str, list[str]], min_labelled: int = 3, min_purity: float = 0.8) -> dict[str, dict]:
    out = {}
    for key, devices in groups.items():
        known = Counter(d for d in devices if d not in ("unknown", None))
        labelled = sum(known.values())
        label, purity = None, None
        if known:
            top, count = known.most_common(1)[0]
            purity = round(count / labelled, 2)
            if labelled >= min_labelled and purity >= min_purity:
                label = top
        out[key] = {"size": len(devices), "labelled": labelled, "purity": purity, "label": label, "known": dict(known)}
    return out


UA_DEVICE = [
    (re.compile(r"iphone|ipod", re.I), "phone"),
    (re.compile(r"ipad", re.I), "tablet"),
    (re.compile(r"android.*mobile|windows phone|blackberry", re.I), "phone"),
    (re.compile(r"android", re.I), "tablet"),
    (re.compile(r"windows nt|macintosh|mac os x|x11|linux|cros", re.I), "desktop"),
]

CLIENT_INFO_RULES: list[tuple[re.Pattern, str, str, str, str]] = [
    (re.compile(r"^client=activesync", re.I), "unknown", "Exchange ActiveSync (usually a phone or tablet app; Outlook 2013+ for Outlook.com also uses it)", "exchange_activesync", "service"),
    (re.compile(r"^client=outlookservice;.*windowscommunicationsapps", re.I), "desktop", "Windows Mail app", "exchange_outlookservice", "service"),
    (re.compile(r"^client=outlookservice", re.I), "phone", "Outlook mobile (OutlookService)", "exchange_outlookservice", "service"),
    (re.compile(r"^client=owa", re.I), "web", "Outlook on the web", "exchange_owa", "service"),
    (re.compile(r"^client=(msexchangerpc|outlook|mapi)", re.I), "desktop", "Outlook desktop (MAPI)", "exchange_mapi", "service"),
    (re.compile(r"^client=rest", re.I), "unknown", "REST API client", "exchange_rest", "service"),
    (re.compile(r"^client=webservices", re.I), "unknown", "Exchange Web Services client", "exchange_ews", "service"),
    (re.compile(r"^client=hub transport;.*isclientsubmission=true", re.I), "unknown", "SMTP client submission", "smtp_submission", "client"),
    (re.compile(r"^client=(eba|tba|hub transport|transport)", re.I), "server", "server-side assistant or transport", "exchange_server", "service"),
]


def client_info(props: dict | None) -> str | None:
    if not props:
        return None
    for k, v in props.items():
        if k.lower().endswith(":clientinfo:0x001f"):
            value = v.get("value")
            return str(value) if value else None
    return None


def original_client_ip(props: dict | None) -> str | None:
    if not props:
        return None
    for k, v in props.items():
        if "x-ms-exchange-organization-originalclientipaddress" in k.lower():
            value = v.get("value")
            return str(value).strip() if value else None
    return None


def classify_client_info(value: str) -> Writer | None:
    for rx, device, label, path, by in CLIENT_INFO_RULES:
        if rx.search(value):
            w = Writer(device=device, client=label, path=path, date_by=by, basis=[f"Exchange ClientInfo: {value[:100]}"])
            if path == "exchange_owa":
                for ua, ua_device in UA_DEVICE:
                    if ua.search(value):
                        w.device = "phone" if ua_device == "phone" else ("tablet" if ua_device == "tablet" else "desktop")
                        w.client = f"Outlook on the web ({w.device} browser)"
                        break
            return w
    return None


def merge(primary: Writer, extra: Writer | None) -> Writer:
    if extra is None:
        return primary
    out = Writer(primary.device, primary.client, primary.path, primary.date_by, [*primary.basis, *extra.basis])
    if out.device in ("unknown",) and extra.device not in ("unknown",):
        out.device = extra.device
    elif extra.device not in ("unknown", "server") and out.device != extra.device and extra.device != "web":
        out.basis.append(f"ClientInfo device {extra.device} differs from {out.device}")
    if out.path == "unknown":
        out.path, out.date_by = extra.path, extra.date_by
    out.client = extra.client or out.client
    return out
