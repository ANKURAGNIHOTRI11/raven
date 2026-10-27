"""Telegram channel watcher.

Chat platforms are the lowest-trust, highest-injection-risk source RAVEN
ingests: no schema, no editorial process, and text written specifically to
be read by humans in a feed - exactly the shape prompt injection takes.
There is no shortcut here: every message that mentions a CVE goes through
the identical put_raw -> RawDocument -> normalizer pipeline as NVD or any
other source, lands with the lowest trust score in the registry, and is
subject to the same adversarial screening before it ever reaches an LLM.
See docs/threat-model.md SS3.1 - nothing about "it's just a chat message"
exempts it from that.

--------------------------------------------------------------------------
One-time setup (cannot happen inside the container - MTProto login needs an
interactive one-time code on first use, and this service is meant to run
unattended after that):

    pip install telethon
    python3 - <<'PY'
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

api_id = int(input("api_id: "))
api_hash = input("api_hash: ")
with TelegramClient(StringSession(), api_id, api_hash) as client:
    print("\nRAVEN_TELEGRAM_SESSION=" + client.session.save())
PY

Run that once from any machine with network access (your laptop is fine),
answer the phone-number/OTP prompts, and paste the printed line into .env.
The resulting string is a bearer credential for whatever Telegram account
you logged in with - handle it like a password: never commit it, restrict
.env permissions, rotate it (log out the session in Telegram's own
Settings -> Devices) if it ever leaks.

RAVEN_TELEGRAM_CHANNELS is a comma-separated list of channel usernames
(no @, no t.me/ prefix) to watch, e.g. "some_channel,another_channel".
This repo does not ship a default channel list - pick channels
deliberately, the same way you'd choose any other intel source.
--------------------------------------------------------------------------
"""
from __future__ import annotations

import asyncio
import hashlib
import re

from telethon import TelegramClient, events
from telethon.sessions import StringSession

from raven_common import bus, db, storage, topics
from raven_common.models import RawDocument, SourceClass
from raven_common.runtime import bootstrap, run
from raven_common.metrics import ERRORS

SERVICE = "telegram_watcher"
SOURCE_ID = "telegram"
TRUST = 0.25  # floor of the registry - unauthenticated public chat content
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
settings, log = bootstrap(SERVICE)


def doc_id_for(channel: str, msg_id: int, cve_id: str) -> str:
    return hashlib.sha256(f"telegram:{channel}:{msg_id}:{cve_id}".encode()).hexdigest()[:40]


def configured_channels() -> list[str]:
    return [c.strip() for c in (settings.telegram_channels or "").split(",") if c.strip()]


async def idle_forever(reason: str) -> None:
    log.warning("telegram_watcher_idle", reason=reason)
    while True:
        await asyncio.sleep(3600)


async def publish_mention(producer: bus.Producer, channel: str, msg_id: int, text: str) -> None:
    cves = sorted(set(CVE_RE.findall(text)))
    if not cves:
        return
    object_key, digest = await asyncio.to_thread(
        storage.put_raw, SOURCE_ID, text.encode("utf-8", "replace"), "text/plain",
    )
    maturity = ("poc" if re.search(r"\b(exploit|poc|in the wild|weaponi[sz]ed)\b", text, re.I)
                else "none")
    for cve_id in cves:
        rec = {
            "cve_id": cve_id,
            "title": f"Telegram mention in @{channel}",
            "description": text[:4000],
            "references": [{"url": f"https://t.me/{channel}/{msg_id}", "tags": ["telegram"]}],
            "exploit_maturity": maturity,
        }
        doc = RawDocument(
            doc_id=doc_id_for(channel, msg_id, cve_id),
            source_id=SOURCE_ID,
            source_class=SourceClass.MEDIA,
            url=f"https://t.me/{channel}",
            content_sha256=digest,
            content_type="text/plain",
            object_key=object_key,
            payload=rec,
            trust=TRUST,
        )
        try:
            async with db.conn() as c:
                await c.execute(
                    "INSERT INTO raw_documents (doc_id, source_id, url, content_sha256, "
                    "content_type, object_key) VALUES ($1,$2,$3,$4,$5,$6) "
                    "ON CONFLICT (doc_id) DO NOTHING",
                    doc.doc_id, doc.source_id, doc.url, doc.content_sha256,
                    doc.content_type, doc.object_key,
                )
            await producer.send(topics.RAW_DOCUMENTS, doc, key=cve_id)
            log.info("telegram_cve_mention", channel=channel, cve=cve_id, msg_id=msg_id)
        except Exception as exc:
            ERRORS.labels(SERVICE, "publish").inc()
            log.warning("telegram_publish_failed", error=str(exc)[:300])


async def main() -> None:
    if not (settings.telegram_api_id and settings.telegram_api_hash and settings.telegram_session):
        await idle_forever("RAVEN_TELEGRAM_API_ID/HASH/SESSION not set")
        return
    channels = configured_channels()
    if not channels:
        await idle_forever("RAVEN_TELEGRAM_CHANNELS is empty - nothing to watch")
        return

    await bus.wait_for_bus()
    await bus.ensure_topics(topics.ALL_TOPICS)
    await asyncio.to_thread(storage.ensure_bucket)
    producer = await bus.Producer(SERVICE).start()

    client = TelegramClient(
        StringSession(settings.telegram_session),
        int(settings.telegram_api_id),
        settings.telegram_api_hash,
    )

    @client.on(events.NewMessage(chats=channels))
    async def handler(event) -> None:
        text = event.raw_text or ""
        if not text:
            return
        channel = getattr(event.chat, "username", None) or str(event.chat_id)
        await publish_mention(producer, channel, event.id, text)

    log.info("telegram_watching", channels=channels)
    await client.start()
    await client.run_until_disconnected()


if __name__ == "__main__":
    run(main, SERVICE)
