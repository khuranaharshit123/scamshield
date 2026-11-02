"""FastAPI entry point: `uvicorn app.main:app`."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import jobs
from app.api import admin, v1
from app.db import create_all, dispose


@asynccontextmanager
async def lifespan(_: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Creates missing tables only (idempotent). Move to Alembic migrations once the schema settles.
    await create_all()
    yield
    await jobs.drain()
    await dispose()


app = FastAPI(title="ScamShield API", version="0.1.0", lifespan=lifespan)
app.include_router(v1.router)
app.include_router(admin.router)
