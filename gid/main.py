"""Uvicorn entrypoint: uvicorn gid.main:app."""

from .app import app, create_app

__all__ = ["app", "create_app"]
