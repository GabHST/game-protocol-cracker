"""Optional protobuf decoding helpers.

Two modes:

* **schema-less** - uses :mod:`blackboxprotobuf` if installed. Produces
  nested dicts keyed by field number.
* **schema** - not implemented here; a ``.proto`` file can be compiled
  externally with ``protoc`` and the generated Python module can decode
  the bytes. We expose :func:`decode_with_module` for that path.

Both helpers degrade gracefully to ``None`` when the payload fails to
parse so decoders can be chained.
"""

from __future__ import annotations

from typing import Any


def decode_schemaless(payload: bytes) -> Any | None:
    """Decode a protobuf blob with :mod:`blackboxprotobuf` if available.

    Returns ``None`` if the library is missing or parsing fails.
    """
    try:
        import blackboxprotobuf  # type: ignore
    except ImportError:
        return None
    try:
        obj, _typedef = blackboxprotobuf.decode_message(payload)
        return obj
    except Exception:
        return None


def decode_with_module(
    payload: bytes,
    module,  # protoc-generated Python module
    message_name: str,
) -> Any | None:
    """Decode ``payload`` using a schema-compiled protobuf message class."""
    cls = getattr(module, message_name, None)
    if cls is None:
        return None
    try:
        msg = cls()
        msg.ParseFromString(payload)
        return msg
    except Exception:
        return None
