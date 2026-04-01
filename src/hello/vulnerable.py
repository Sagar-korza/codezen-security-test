"""
Intentionally vulnerable module — used to verify Semgrep SAST detection.
DO NOT use in production.
"""

import subprocess
import pickle
import hashlib


# B102 / python.lang.security.audit.exec-detected
# Semgrep: exec() with user input — code injection
def run_command(user_input: str) -> None:
    exec(user_input)  # noqa: S102


# B602 / python.lang.security.audit.subprocess-shell-true
# Semgrep: subprocess with shell=True — command injection
def ping_host(hostname: str) -> str:
    result = subprocess.run(
        f"ping -c 1 {hostname}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


# B301 / python.lang.security.audit.pickle
# Semgrep: pickle.loads on untrusted data — arbitrary code execution
def load_session(data: bytes) -> object:
    return pickle.loads(data)  # noqa: S301


# B303 / python.lang.security.audit.use-of-md5
# Semgrep: MD5 is cryptographically weak
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # noqa: S324


# B105 / python.lang.security.audit.hardcoded-password-string
# Semgrep: hardcoded credentials
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-abcdef1234567890abcdef1234567890"


# B608 / python.lang.security.audit.formatted-sql-query
# Semgrep: SQL injection via string formatting
def get_user(username: str) -> str:
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return query
