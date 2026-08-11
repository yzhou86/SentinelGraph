from ocskg.config import Settings
from ocskg.repository import StarRocksRepository


def test_connection_info_masks_password_and_reports_tls_state() -> None:
    repository = StarRocksRepository(
        Settings(
            starrocks_host="external.example",
            starrocks_port=19030,
            starrocks_user="ocskg_reader",
            starrocks_password="must-not-leak",
            starrocks_database="security_prod",
            starrocks_ssl_enabled=True,
            starrocks_ssl_verify=True,
        )
    )

    info = repository.connection_info()

    assert info == {
        "host": "external.example",
        "port": 19030,
        "user": "ocskg_reader",
        "database": "security_prod",
        "tls": {"enabled": True, "verify_server": True, "custom_ca_configured": False},
        "connect_timeout_seconds": 5,
    }
    assert "must-not-leak" not in str(info)


def test_connection_passes_tls_options_to_pymysql(monkeypatch) -> None:
    captured = {}

    class FakeConnection:
        def close(self) -> None:
            pass

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return FakeConnection()

    monkeypatch.setattr("ocskg.repository.pymysql.connect", fake_connect)
    repository = StarRocksRepository(
        Settings(
            starrocks_host="external.example",
            starrocks_password="secret",
            starrocks_ssl_enabled=True,
            starrocks_ssl_verify=False,
        )
    )

    with repository.connection():
        pass

    assert captured["host"] == "external.example"
    assert captured["password"] == "secret"
    assert captured["ssl"] == {"check_hostname": False}
