import hashlib
import uuid
from pathlib import Path
from typing import BinaryIO, Protocol

from netlens.parsing import CaptureError


class Storage(Protocol):
    def save(self, stream: BinaryIO, limit: int) -> tuple[str, int, str]: ...
    def path(self, name: str) -> Path: ...
    def delete(self, name: str) -> None: ...


class LocalStorage:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def path(self, name: str) -> Path:
        if Path(name).name != name or not name.endswith(".capture"):
            raise ValueError("Invalid storage name")
        return self.root / name

    def save(self, stream: BinaryIO, limit: int) -> tuple[str, int, str]:
        name = f"{uuid.uuid4().hex}.capture"
        digest, total = hashlib.sha256(), 0
        try:
            with self.path(name).open("xb") as out:
                while chunk := stream.read(65536):
                    total += len(chunk)
                    if total > limit:
                        raise CaptureError("Upload size limit exceeded.", "upload_limit")
                    digest.update(chunk)
                    out.write(chunk)
            return name, total, digest.hexdigest()
        except BaseException:
            self.delete(name)
            raise

    def delete(self, name: str) -> None:
        self.path(name).unlink(missing_ok=True)
