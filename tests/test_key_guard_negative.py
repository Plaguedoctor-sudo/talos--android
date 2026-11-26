# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Negative and positive fixture tests for pre-commit-key-guard.sh and key-guard.sh."""

from pathlib import Path
import subprocess

REPO_ROOT = Path(__file__).resolve().parent.parent
PRE_COMMIT_GUARD = REPO_ROOT / "scripts" / "pre-commit-key-guard.sh"
KEY_GUARD = REPO_ROOT / "scripts" / "key-guard.sh"
# Construct dynamically so this test source file does not trigger key-guard blob scans itself.
SYNTHETIC_PEM_HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"


def _init_temp_git_repo(repo_dir: Path) -> None:
    """Initialize an isolated git repo with local-only identity config."""
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@talos.invalid"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "TALOS Test"], cwd=repo_dir, check=True)


def test_staged_private_key_blocked(tmp_path):
    """CASE A: staged file starting with an OpenSSH private key header is blocked."""
    repo_dir = tmp_path / "repo_staged"
    repo_dir.mkdir()
    _init_temp_git_repo(repo_dir)

    offending = repo_dir / "notes" / "secret_note.txt"
    offending.parent.mkdir(parents=True)
    offending.write_text(
        f"{SYNTHETIC_PEM_HEADER}\nbenign body line 1\nbenign body line 2\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "notes/secret_note.txt"], cwd=repo_dir, check=True)

    res = subprocess.run(
        ["bash", str(PRE_COMMIT_GUARD)],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0


def test_committed_blob_private_key_blocked(tmp_path):
    """CASE B: committed blob with private key header is blocked and stderr names the path."""
    repo_dir = tmp_path / "repo_committed"
    repo_dir.mkdir()
    _init_temp_git_repo(repo_dir)

    rel_path = "docs/leaked_key_material.txt"
    offending = repo_dir / rel_path
    offending.parent.mkdir(parents=True)
    offending.write_text(
        f"{SYNTHETIC_PEM_HEADER}\nbenign body line 1\nbenign body line 2\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", rel_path], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "add fixture"], cwd=repo_dir, check=True, capture_output=True)

    res = subprocess.run(
        ["bash", str(KEY_GUARD)],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0
    assert rel_path in res.stderr


def test_clean_repo_passes_both_guards(tmp_path):
    """CASE C: clean repository with benign committed content passes both key guards."""
    repo_dir = tmp_path / "repo_clean"
    repo_dir.mkdir()
    _init_temp_git_repo(repo_dir)

    benign = repo_dir / "README.txt"
    benign.write_text("Benign sovereign test artifact.\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.txt"], cwd=repo_dir, check=True)

    staged_res = subprocess.run(
        ["bash", str(PRE_COMMIT_GUARD)],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    assert staged_res.returncode == 0, staged_res.stderr

    subprocess.run(["git", "commit", "-m", "clean commit"], cwd=repo_dir, check=True, capture_output=True)

    pre_commit_clean = subprocess.run(
        ["bash", str(PRE_COMMIT_GUARD)],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    blob_clean = subprocess.run(
        ["bash", str(KEY_GUARD)],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    assert pre_commit_clean.returncode == 0, pre_commit_clean.stderr
    assert blob_clean.returncode == 0, blob_clean.stderr
