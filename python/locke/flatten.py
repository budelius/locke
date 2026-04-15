"""Config flattening — nested JSON to SCREAMING_SNAKE_CASE key-value pairs.

Collision detection raises CollisionError with both source paths.
Keys are sorted alphabetically for deterministic output.
"""

from locke.errors import CollisionError


def flatten_config(config: dict, _prefix: str = "", _path: str = "") -> dict[str, str]:
    """Flatten nested JSON config to SCREAMING_SNAKE_CASE key-value pairs.

    Args:
        config: Nested JSON config dict.

    Returns:
        Flat dictionary with SCREAMING_SNAKE_CASE keys, sorted alphabetically.

    Raises:
        CollisionError: If two source paths produce the same flattened key.
    """
    result: dict[str, str] = {}
    sources: dict[str, str] = {}  # key -> source path for collision detection

    _flatten_recursive(config, _prefix, _path, result, sources)

    # Sort alphabetically
    return dict(sorted(result.items()))


def _flatten_recursive(
    obj: dict,
    prefix: str,
    path: str,
    result: dict[str, str],
    sources: dict[str, str],
) -> None:
    for key, value in obj.items():
        flat_key = f"{prefix}{key}".upper() if not prefix else f"{prefix}_{key}".upper()
        source_path = f"{path}{key}" if not path else f"{path}.{key}"

        if isinstance(value, dict):
            _flatten_recursive(value, flat_key, source_path, result, sources)
        else:
            if flat_key in result:
                raise CollisionError(flat_key, sources[flat_key], source_path)
            result[flat_key] = str(value)
            sources[flat_key] = source_path
