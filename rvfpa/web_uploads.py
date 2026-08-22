"""Web上传字段校验模块。

浏览器通过JSON提交Base64编码的ELF和MAP文件。本模块集中完成成对字段检查、
Base64解码、空文件判断、文件名净化和大小限制，HTTP层只负责读取请求体。
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import Any

from .constants import MAX_UPLOAD_BYTES
from .errors import InputValidationError


def decode_uploaded_file(
    payload: dict[str, Any],
    prefix: str,
) -> tuple[str, bytes] | None:
    """解析一组 ``<prefix>_name`` 与 ``<prefix>_base64`` 上传字段。

    两个字段都未提供时返回 ``None``，适合MAP等可选文件；只提供其中一个字段、
    内容不是合法Base64、文件为空或超过限制时抛出可展示给用户的校验错误。
    """

    name = str(payload.get(f"{prefix}_name", "")).strip()
    encoded = payload.get(f"{prefix}_base64")
    if not name and not encoded:
        return None
    if not name or not isinstance(encoded, str):
        raise InputValidationError(
            f"Both {prefix}_name and {prefix}_base64 are required"
        )
    try:
        content = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InputValidationError(f"Invalid Base64 data for {prefix}") from exc
    if not content:
        raise InputValidationError(f"Uploaded {prefix} file is empty")
    if len(content) > MAX_UPLOAD_BYTES:
        raise InputValidationError(
            f"Uploaded {prefix} file exceeds the size limit"
        )
    return Path(name).name, content
