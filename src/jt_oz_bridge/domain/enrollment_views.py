"""Readonly views of trusted append-only enrollment, never catalog promotion.

Only trusted composition builds these views. Plain mappings still become frozen
copies, retaining the original isolation boundary for ordinary callers.
"""

from collections.abc import Callable, Iterable, Iterator, Mapping, Set
from types import MappingProxyType
from typing import Any


class EnrollmentView[K, V](Mapping[K, V]):
    def __init__(self, read: Callable[[], Mapping[K, V]]) -> None:
        self._read = read

    def __getitem__(self, key: K) -> V:
        return self._read()[key]

    def __iter__(self) -> Iterator[K]:
        return iter(tuple(self._read()))

    def __len__(self) -> int:
        return len(self._read())


def readonly_enrollment[K, V](values: Mapping[K, V]) -> Mapping[K, V]:
    return values if isinstance(values, EnrollmentView) else MappingProxyType(dict(values))


def enrollment_projection[K, E, V](
    entries: Mapping[K, E], project: Callable[[E], V | None]
) -> EnrollmentView[K, V]:
    def read() -> Mapping[K, V]:
        return {
            key: value
            for key, entry in tuple(entries.items())
            if (value := project(entry)) is not None
        }

    return EnrollmentView(read)


def enrollment_union[K, V](sources: Iterable[Mapping[K, V]]) -> EnrollmentView[K, V]:
    selected = tuple(sources)

    def read() -> Mapping[K, V]:
        result: dict[K, V] = {}
        for source in selected:
            for key, value in tuple(source.items()):
                if key in result:
                    raise ValueError("enrollment_resource_reference_is_ambiguous")
                result[key] = value
        return result

    return EnrollmentView(read)


class EnrollmentKeys[K](Set[K]):
    def __init__(self, values: EnrollmentView[K, Any]) -> None:
        self._values = values

    def __contains__(self, value: object) -> bool:
        return value in self._values

    def __iter__(self) -> Iterator[K]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    @classmethod
    def _from_iterable[T](cls, values: Iterable[T]) -> Set[T]:
        # ABC Set mixins must not construct a live view over an iterator.
        return frozenset(values)


def readonly_enrollment_keys[K](values: Set[K]) -> Set[K]:
    return values if isinstance(values, EnrollmentKeys) else frozenset(values)
