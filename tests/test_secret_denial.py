"""Tests for secret-read denial."""

from gptme_grimdall.secret_denial import (
    check_secret_path,
    is_secret_path,
    scan_command,
)


def test_blocks_ssh_private_key():
    assert is_secret_path("~/.ssh/id_rsa")
    assert is_secret_path("/home/user/.ssh/id_ed25519")


def test_blocks_aws_credentials():
    assert is_secret_path("~/.aws/credentials")


def test_blocks_env_file():
    assert is_secret_path(".env")
    assert is_secret_path("/project/.env.production")


def test_blocks_pem():
    assert is_secret_path("server.pem")


def test_blocks_config_dir():
    assert is_secret_path("~/.config/foo")


def test_blocks_keychain():
    assert is_secret_path("~/Library/Keychains/login.keychain-db")


def test_allows_normal_files():
    assert not is_secret_path("README.md")
    assert not is_secret_path("src/main.py")


def test_check_secret_path_reason():
    reason = check_secret_path("~/.ssh/id_rsa")
    assert reason is not None
    assert "~/.ssh/id_rsa" in reason


def test_scan_command_catches_cat_secret():
    assert scan_command("cat ~/.ssh/id_rsa") is not None


def test_scan_command_allows_benign():
    assert scan_command("cat README.md") is None
