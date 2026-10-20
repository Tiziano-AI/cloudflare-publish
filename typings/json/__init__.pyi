from collections.abc import Callable

type JSONScalar = None | bool | int | float | str
type JSONValue = JSONScalar | list[JSONValue] | dict[str, JSONValue]

class JSONDecodeError(ValueError):
    msg: str
    doc: str
    pos: int
    lineno: int
    colno: int

class JSONDecoder: ...
class JSONEncoder: ...

def loads(
    s: str | bytes | bytearray,
    *,
    cls: type[JSONDecoder] | None = ...,
    object_hook: Callable[[dict[str, object]], object] | None = ...,
    parse_float: Callable[[str], object] | None = ...,
    parse_int: Callable[[str], object] | None = ...,
    parse_constant: Callable[[str], object] | None = ...,
    object_pairs_hook: Callable[[list[tuple[str, object]]], object] | None = ...,
    **kwds: object,
) -> JSONValue: ...
def dumps(
    obj: object,
    *,
    skipkeys: bool = ...,
    ensure_ascii: bool = ...,
    check_circular: bool = ...,
    allow_nan: bool = ...,
    cls: type[JSONEncoder] | None = ...,
    indent: int | str | None = ...,
    separators: tuple[str, str] | None = ...,
    default: Callable[[object], object] | None = ...,
    sort_keys: bool = ...,
    **kwds: object,
) -> str: ...
