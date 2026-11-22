"""Canonical locales and context-independent message formatting."""

import json
import logging
import string
import time
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from sqlalchemy import delete, select

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.security.root_files import root_bytes
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Preference


class Translator:
    def __init__(self) -> None:
        self.catalogs: dict[str, dict[str, str]] = {
            locale: json.loads(files(__package__).joinpath(f"{locale}.json").read_text())
            for locale in ("en", "zh-TW")
        }
        if self.catalogs["en"].keys() != self.catalogs["zh-TW"].keys():
            raise ValueError("translation key mismatch")
        for key, text in self.catalogs["en"].items():
            if self.fields(text) != self.fields(self.catalogs["zh-TW"][key]):
                raise ValueError("translation parameter mismatch")

    @staticmethod
    def fields(text: str) -> set[str]:
        return {name for _, name, _, _ in string.Formatter().parse(text) if name is not None}

    def render(self, key: str, locale: Locale = "en", /, **params: Any) -> str:
        if key not in self.catalogs["en"]:
            logging.getLogger(__name__).warning("translation_key_missing")
            return self.catalogs[locale]["error.generic"]
        text = self.catalogs[locale].get(key)
        if text is None:
            logging.getLogger(__name__).warning("translation_fallback")
            text = self.catalogs["en"][key]
        if set(params) != self.fields(text):
            raise ValueError("translation parameters mismatch")
        # Escaping belongs to the output target (e.g. Jinja autoescape), not this layer.
        return text.format(**params)

    def page_prefix(self, locale: Locale, index: int, total: int) -> str:
        """A lone page needs no page header."""
        return (
            ""
            if total == 1
            else self.render("output.page", locale, index=index, total=total) + "\n\n"
        )


async def save_locale(
    db: Database, principal: str, locale: Locale, *, fence: ConsumerFence | None = None
) -> None:
    if locale not in {"en", "zh-TW"}:
        raise ValueError("unsupported locale")
    async with db.sessions.begin() as session:
        if fence is not None:
            await fence.lock(session)
        value = await session.get(Preference, principal)
        if value:
            value.locale = locale
        else:
            session.add(Preference(principal=principal, locale=locale))


async def get_locale(db: Database, principal: str, default: Locale = "en") -> Locale:
    async with db.sessions() as session:
        value = await session.scalar(
            select(Preference.locale).where(Preference.principal == principal)
        )
        return value if value in {"en", "zh-TW"} else default  # type: ignore[return-value]


async def clear_locale(db: Database, principal: str, *, fence: ConsumerFence) -> None:
    async with db.sessions.begin() as session:
        await fence.lock(session)
        await session.execute(delete(Preference).where(Preference.principal == principal))


def platform_locale(
    path: Path, realm: str, user_id: int, *, now: float | None = None
) -> Locale | None:
    """Read only a bounded, fresh root-managed export, never a chat-supplied path."""
    try:
        value = strict_loads(root_bytes(path, maximum=65536))
        if (
            not isinstance(value, dict)
            or set(value) != {"format", "realm_id", "generated_at", "users"}
            or value["format"] != "jt-oz-user-languages-v1"
            or value["realm_id"] != realm
            or type(value["generated_at"]) not in {int, float}
            or not 0 <= (time.time() if now is None else now) - value["generated_at"] <= 300
            or not isinstance(value["users"], dict)
            or len(value["users"]) > 10000
        ):
            return None
        raw = value["users"].get(str(user_id))
        if not isinstance(raw, str) or len(raw) > 32:
            return None
        language = raw.lower().replace("_", "-")
        if language in {"zh-tw", "zh-hant", "zh-hant-tw", "zh-hk", "zh-mo"}:
            return "zh-TW"
        if language == "en" or language.startswith("en-"):
            return "en"
    except (OSError, ValueError, TypeError):
        pass
    return None


async def message_locale(
    db: Database, reader: SourceReader, message: HumanMessage, default: Locale | None = None
) -> Locale:
    """Explicit bridge preference wins; otherwise follow trusted platform metadata."""
    principal = f"user:{message.realm_id}:{message.author_id}"
    async with db.sessions() as session:
        explicit = await session.scalar(
            select(Preference.locale).where(Preference.principal == principal)
        )
    if explicit in {"en", "zh-TW"}:
        return cast(Locale, explicit)
    resolve = getattr(reader, "preferred_locale", None)
    if callable(resolve):
        language = await resolve(message.realm_id, message.author_id)
        if language in {"en", "zh-TW"}:
            return cast(Locale, language)
    fallback = default if default is not None else getattr(reader, "default_locale", "en")
    return cast(Locale, fallback) if fallback in {"en", "zh-TW"} else "en"
