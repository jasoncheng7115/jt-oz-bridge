"""Which live Zulip servers still match an enrollment qualified on one release."""

from __future__ import annotations


def release_series(version: object) -> str | None:
    """`12` for a plain `12.5` release; None for development or unknown builds."""
    if type(version) is not str:
        return None
    major, dot, minor = version.partition(".")
    if not dot or not major.isdigit() or not minor.isdigit():
        return None
    return major


def same_release_line(
    qualified_version: str, qualified_level: int, live_version: object, live_level: object
) -> bool:
    """The qualified release itself, or a later maintenance release of the same series.

    Zulip ships security fixes as maintenance releases (12.3 to 12.5) and keeps
    their API: a feature level only grows, and maintenance releases take levels
    reserved for them. So the enrollment still holds and a security upgrade does
    not stop the bridge. A new major release (13.0) or a development build still
    needs its own qualification.
    """
    if type(live_level) is not int or type(live_version) is not str:
        return False
    if (live_version, live_level) == (qualified_version, qualified_level):
        return True
    series = release_series(qualified_version)
    return (
        series is not None
        and release_series(live_version) == series
        and live_level >= qualified_level
        and int(live_version.partition(".")[2]) >= int(qualified_version.partition(".")[2])
    )
