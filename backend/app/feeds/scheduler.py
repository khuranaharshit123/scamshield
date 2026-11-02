"""Long-running feed refresher for the `feed-sync` container (phase 1 replacement for Celery beat).

  openphish, urlhaus           every hour
  phishing_db (domains, links) every 24 hours
"""
from __future__ import annotations

import asyncio
import logging
import time

from app.db import create_all
from app.feeds.sync import sync_feed

log = logging.getLogger("feed-scheduler")
SCHEDULE = {"openphish": 3600, "urlhaus": 3600, "phishing_db_domains": 86400, "phishing_db_links": 86400}


async def run_forever() -> None:
    await create_all()
    last: dict[str, float] = {}
    while True:
        now = time.time()
        for name, every in SCHEDULE.items():
            if now - last.get(name, 0) >= every:
                try:
                    n = await sync_feed(name)
                    log.info("synced %s (%d)", name, n)
                except Exception as e:
                    log.error("feed %s failed: %s", name, e)
                last[name] = now
        await asyncio.sleep(60)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(run_forever())
