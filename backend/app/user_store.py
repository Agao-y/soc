import json
from pathlib import Path

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_data_file = Path(__file__).resolve().parents[2] / "data" / "users.json"


def _load() -> dict:
    if not _data_file.exists():
        _data_file.parent.mkdir(parents=True, exist_ok=True)
        default = {"admin": {"username": "admin", "hashed_password": pwd_context.hash("admin123"), "role": "admin"}}
        _data_file.write_text(json.dumps(default, ensure_ascii=False, indent=2), encoding="utf-8")
        return default
    return json.loads(_data_file.read_text(encoding="utf-8"))


def _save(users: dict) -> None:
    _data_file.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")


def get_user(username: str) -> dict | None:
    return _load().get(username)


def list_users() -> list[dict]:
    return [{"username": u, "role": d["role"]} for u, d in _load().items()]


def create_user(username: str, password: str, role: str = "analyst") -> dict | None:
    users = _load()
    if username in users:
        return None
    users[username] = {"username": username, "hashed_password": pwd_context.hash(password), "role": role}
    _save(users)
    return {"username": username, "role": role}


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def authenticate_user(username: str, password: str) -> dict | None:
    user = get_user(username)
    if not user or not verify_password(password, user.get("hashed_password", "")):
        return None
    return user
