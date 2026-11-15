"""Contract tests for the typed REST transport (``sophos_firewall_mcp.client``).

Every test runs against RESPX: no firewall, no network, no real credentials. The tests prove the
exact request each primitive builds, the status/error mapping, the read-retry and write-ambiguity
policy, the pagination helper and the secret-handling guarantees.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from sophos_firewall_mcp import client as client_module
from sophos_firewall_mcp.client import SophosRestClient
from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.errors import (
    SophosAmbiguousWriteError,
    SophosAPIError,
    SophosAuthError,
    SophosConflictError,
    SophosNotFoundError,
    SophosTransportError,
    SophosValidationError,
)

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"

PAGE_BODY: dict[str, Any] = {
    "items": [{"name": "allow-lan", "id": "1"}],
    "pages": {"current": 2, "size": 10, "maxSize": 100, "total": 47, "items": 10},
}


# -- Helpers and fixtures ----------------------------------------------------


def make_settings(**overrides: str) -> Settings:
    env = {"SOPHOS_HOST": HOST, "SOPHOS_API_KEY": KEY}
    env.update(overrides)
    return Settings.from_env(env)


def make_client(**overrides: str) -> SophosRestClient:
    return SophosRestClient(make_settings(**overrides))


async def call(client: SophosRestClient, method: str, path: str) -> Any:
    """Invoke one primitive by HTTP method, for parametrized tests."""
    if method == "GET":
        return await client.get(path)
    if method == "POST":
        return await client.post(path, json={})
    if method == "PATCH":
        return await client.patch(path, json={})
    return await client.delete(path)


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the backoff sleep and record the delays, so retries are instant and deterministic."""
    recorded: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        recorded.append(seconds)

    monkeypatch.setattr(client_module, "_sleep", fake_sleep)
    return recorded


def assert_no_key(error: BaseException) -> None:
    for text in (str(error), repr(error), repr(error.args)):
        assert KEY not in text


# -- Request shape per primitive ---------------------------------------------


async def test_get_request_shape(router: Any) -> None:
    path = "/network/dns/protection/status"
    route = router.get(f"{BASE}{path}").mock(
        return_value=httpx.Response(200, json={"status": "active"})
    )
    client = make_client()
    try:
        assert await client.get(path) == {"status": "active"}
    finally:
        await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert str(request.url) == f"{BASE}{path}"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["accept"] == "application/json"
    assert "content-type" not in request.headers
    assert request.content == b""


async def test_get_query_parameters(router: Any) -> None:
    path = "/firewall/rules/ipv4"
    route = router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json={"items": []}))
    client = make_client()
    try:
        await client.get(path, params={"page": 2, "pageSize": 10, "pageTotal": True})
    finally:
        await client.aclose()

    assert str(route.calls.last.request.url) == f"{BASE}{path}?page=2&pageSize=10&pageTotal=true"


async def test_post_request_shape(router: Any) -> None:
    path = "/firewall/rules/ipv4"
    body = {"name": "allow-lan", "enabled": False}
    route = router.post(f"{BASE}{path}").mock(
        return_value=httpx.Response(201, json={"name": "allow-lan", "enabled": False})
    )
    client = make_client()
    try:
        assert await client.post(path, json=body) == {"name": "allow-lan", "enabled": False}
    finally:
        await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert str(request.url) == f"{BASE}{path}"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["accept"] == "application/json"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == body


async def test_patch_request_shape(router: Any) -> None:
    path = "/nat/rules/ipv4/snat-web"
    body = {"enabled": False, "translatedSource": {"masq": True}}
    route = router.patch(f"{BASE}{path}").mock(return_value=httpx.Response(200, json=body))
    client = make_client()
    try:
        assert await client.patch(path, json=body) == body
    finally:
        await client.aclose()

    request = route.calls.last.request
    assert request.method == "PATCH"
    assert str(request.url) == f"{BASE}{path}"
    assert request.headers["content-type"] == "application/json"
    assert request.headers["content-type"] != "application/merge-patch+json"
    assert json.loads(request.content) == body


async def test_delete_204_returns_none(router: Any) -> None:
    path = "/firewall/rules/ipv4/allow-lan"
    route = router.delete(f"{BASE}{path}").mock(return_value=httpx.Response(204))
    client = make_client()
    try:
        assert await client.delete(path) is None
    finally:
        await client.aclose()

    request = route.calls.last.request
    assert request.method == "DELETE"
    assert str(request.url) == f"{BASE}{path}"
    assert "content-type" not in request.headers
    assert request.content == b""


async def test_get_204_and_empty_body_return_none(router: Any) -> None:
    router.get(f"{BASE}/empty").mock(return_value=httpx.Response(204))
    router.get(f"{BASE}/blank").mock(return_value=httpx.Response(200, content=b""))
    client = make_client()
    try:
        assert await client.get("/empty") is None
        assert await client.get("/blank") is None
    finally:
        await client.aclose()


async def test_write_error_response_is_mapped_not_ambiguous(router: Any) -> None:
    path = "/firewall/rules/ipv4"
    route = router.post(f"{BASE}{path}").mock(
        return_value=httpx.Response(409, json={"error": "conflict"})
    )
    client = make_client()
    try:
        with pytest.raises(SophosConflictError) as info:
            await client.post(path, json={"name": "duplicate"})
    finally:
        await client.aclose()

    assert route.call_count == 1
    assert info.value.status == 409
    assert info.value.error_code == "conflict"


# -- Error mapping -----------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "exception_type"),
    [
        (400, SophosValidationError),
        (401, SophosAuthError),
        (403, SophosAuthError),
        (404, SophosNotFoundError),
        (409, SophosConflictError),
        (500, SophosAPIError),
        (418, SophosAPIError),
    ],
)
async def test_error_status_mapping(router: Any, status: int, exception_type: type) -> None:
    path = "/firewall/rules/ipv4/rule-1"
    route = router.get(f"{BASE}{path}").mock(
        return_value=httpx.Response(
            status,
            json={"error": "someErrorCode", "message": "appliance detail that must not leak"},
        )
    )
    client = make_client()
    try:
        with pytest.raises(exception_type) as info:
            await client.get(path)
    finally:
        await client.aclose()

    assert route.call_count == 1
    error = info.value
    if exception_type is SophosAPIError:
        assert type(error) is SophosAPIError
    assert error.method == "GET"
    assert error.path == path
    assert error.status == status
    assert error.error_code == "someErrorCode"

    message = str(error)
    assert "GET" in message
    assert path in message
    assert str(status) in message
    assert "someErrorCode" in message
    assert "appliance detail that must not leak" not in message
    assert_no_key(error)


async def test_html_404_maps_to_not_found(router: Any) -> None:
    path = "/does-not-exist"
    router.get(f"{BASE}{path}").mock(
        return_value=httpx.Response(
            404,
            headers={"content-type": "text/html"},
            text="<html><body>404 Not Found</body></html>",
        )
    )
    client = make_client()
    try:
        with pytest.raises(SophosNotFoundError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    error = info.value
    assert error.status == 404
    assert error.error_code is None
    assert "<html>" not in str(error)
    assert "Not Found" not in str(error)


async def test_plain_text_405_maps_to_api_error(router: Any) -> None:
    path = "/firewall/rules/ipv4"
    router.get(f"{BASE}{path}").mock(
        return_value=httpx.Response(
            405, headers={"content-type": "text/plain"}, text="Method Not Allowed"
        )
    )
    client = make_client()
    try:
        with pytest.raises(SophosAPIError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    error = info.value
    assert type(error) is SophosAPIError
    assert error.status == 405
    assert error.error_code is None
    assert "Method Not Allowed" not in str(error)


async def test_malformed_json_success_body_fails_safely(router: Any) -> None:
    path = "/network/dns/protection/status"
    router.get(f"{BASE}{path}").mock(
        return_value=httpx.Response(
            200, headers={"content-type": "text/plain"}, text="not json at all"
        )
    )
    client = make_client()
    try:
        with pytest.raises(SophosAPIError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    error = info.value
    assert type(error) is SophosAPIError
    assert error.status == 200
    assert "not valid JSON" in str(error)
    assert "not json at all" not in str(error)


async def test_malformed_json_error_body_still_maps_by_status(router: Any) -> None:
    path = "/firewall/rules/ipv4"
    router.get(f"{BASE}{path}").mock(
        return_value=httpx.Response(
            400, headers={"content-type": "text/html"}, text="<html>bad request</html>"
        )
    )
    client = make_client()
    try:
        with pytest.raises(SophosValidationError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    error = info.value
    assert error.status == 400
    assert error.error_code is None
    assert "<html>" not in str(error)


# -- Read retries ------------------------------------------------------------


async def test_read_timeout_is_retried_once(router: Any, sleeps: list[float]) -> None:
    path = "/network/dns/protection/status"
    route = router.get(f"{BASE}{path}").mock(
        side_effect=[
            httpx.ReadTimeout("read timed out"),
            httpx.Response(200, json={"status": "active"}),
        ]
    )
    client = make_client()
    try:
        assert await client.get(path) == {"status": "active"}
    finally:
        await client.aclose()

    assert route.call_count == 2
    assert len(sleeps) == 1
    assert 0.25 <= sleeps[0] <= 0.5


async def test_connect_timeout_is_retried_then_maps_to_transport_error(
    router: Any, sleeps: list[float]
) -> None:
    path = "/network/dns/protection/status"
    route = router.get(f"{BASE}{path}").mock(
        side_effect=[httpx.ConnectTimeout("connect timed out"), httpx.ConnectTimeout("again")]
    )
    client = make_client()
    try:
        with pytest.raises(SophosTransportError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    assert route.call_count == 2
    assert len(sleeps) == 1
    assert "ConnectTimeout" in str(info.value)


async def test_read_retries_503_then_succeeds(router: Any, sleeps: list[float]) -> None:
    path = "/network/dns/protection/status"
    route = router.get(f"{BASE}{path}").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"status": "active"})]
    )
    client = make_client()
    try:
        assert await client.get(path) == {"status": "active"}
    finally:
        await client.aclose()

    assert route.call_count == 2
    assert len(sleeps) == 1


async def test_read_retries_are_bounded(router: Any, sleeps: list[float]) -> None:
    path = "/network/dns/protection/status"
    route = router.get(f"{BASE}{path}").mock(side_effect=[httpx.Response(503), httpx.Response(503)])
    client = make_client()
    try:
        with pytest.raises(SophosAPIError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    assert info.value.status == 503
    assert route.call_count == 2
    assert len(sleeps) == 1


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 500])
async def test_reads_are_not_retried_for_other_statuses(
    router: Any, sleeps: list[float], status: int
) -> None:
    path = "/firewall/rules/ipv4"
    route = router.get(f"{BASE}{path}").mock(
        return_value=httpx.Response(status, json={"error": "someError"})
    )
    client = make_client()
    try:
        with pytest.raises(SophosAPIError):
            await client.get(path)
    finally:
        await client.aclose()

    assert route.call_count == 1
    assert sleeps == []


async def test_tls_error_is_not_retried(router: Any, sleeps: list[float]) -> None:
    path = "/network/dns/protection/status"
    route = router.get(f"{BASE}{path}").mock(
        side_effect=httpx.ConnectError("SSL: CERTIFICATE_VERIFY_FAILED")
    )
    client = make_client()
    try:
        with pytest.raises(SophosTransportError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    assert route.call_count == 1
    assert sleeps == []
    assert "CERTIFICATE_VERIFY_FAILED" in str(info.value)


async def test_dns_error_maps_to_transport_error(router: Any, sleeps: list[float]) -> None:
    path = "/network/dns/protection/status"
    router.get(f"{BASE}{path}").mock(
        side_effect=httpx.ConnectError("[Errno -3] Temporary failure in name resolution")
    )
    client = make_client()
    try:
        with pytest.raises(SophosTransportError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    assert sleeps == []
    assert "name resolution" in str(info.value)


# -- Write ambiguity ---------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/firewall/rules/ipv4"),
        ("PATCH", "/firewall/rules/ipv4/rule-1"),
        ("DELETE", "/firewall/rules/ipv4/rule-1"),
    ],
)
async def test_write_timeout_is_ambiguous_and_never_retried(
    router: Any, sleeps: list[float], method: str, path: str
) -> None:
    route = router.route(method=method, url=f"{BASE}{path}").mock(
        side_effect=httpx.ReadTimeout("read timed out")
    )
    client = make_client()
    try:
        with pytest.raises(SophosAmbiguousWriteError) as info:
            await call(client, method, path)
    finally:
        await client.aclose()

    assert route.call_count == 1
    assert sleeps == []
    error = info.value
    assert error.method == method
    assert error.path == path
    assert "may have been applied" in str(error)
    assert "reconcile" in str(error)
    assert_no_key(error)


async def test_write_connection_loss_is_ambiguous_and_never_retried(
    router: Any, sleeps: list[float]
) -> None:
    path = "/firewall/rules/ipv4"
    route = router.post(f"{BASE}{path}").mock(side_effect=httpx.ConnectError("connection reset"))
    client = make_client()
    try:
        with pytest.raises(SophosAmbiguousWriteError) as info:
            await client.post(path, json={"name": "allow-lan"})
    finally:
        await client.aclose()

    assert route.call_count == 1
    assert sleeps == []
    assert "ConnectError" in str(info.value)


# -- Path validation ---------------------------------------------------------

INVALID_PATHS = [
    "",
    "network/dns/protection/status",
    "//evil.example/steal",
    "https://evil.example/steal",
    "http://evil.example/steal",
    "/firewall/../administration",
    "/firewall\\rules",
    "/firewall/rules?page=1",
    "/firewall/rules#fragment",
    "/firewall/rules\n",
    " /firewall/rules",
    "/firewall/rules ",
]


@pytest.mark.parametrize("method", ["GET", "POST", "PATCH", "DELETE"])
@pytest.mark.parametrize("path", INVALID_PATHS)
async def test_invalid_path_is_rejected_before_io(router: Any, method: str, path: str) -> None:
    catch_all = router.route().mock(return_value=httpx.Response(200, json={}))
    client = make_client()
    try:
        with pytest.raises(ValueError):
            await call(client, method, path)
    finally:
        await client.aclose()

    assert catch_all.call_count == 0


@pytest.mark.parametrize("path", [None, 123, b"/firewall/rules"])
async def test_non_string_path_is_rejected(router: Any, path: Any) -> None:
    catch_all = router.route().mock(return_value=httpx.Response(200, json={}))
    client = make_client()
    try:
        with pytest.raises(ValueError):
            await client.get(path)
    finally:
        await client.aclose()

    assert catch_all.call_count == 0


async def test_absolute_url_is_rejected(router: Any) -> None:
    catch_all = router.route().mock(return_value=httpx.Response(200, json={}))
    client = make_client()
    try:
        with pytest.raises(ValueError) as info:
            await client.get("https://evil.example/api/firewall-config/v1/firewall/rules")
    finally:
        await client.aclose()

    assert "scheme" in str(info.value) or "absolute" in str(info.value)
    assert catch_all.call_count == 0


# -- Redirects and proxy behaviour -------------------------------------------


async def test_cross_origin_redirect_is_not_followed(router: Any) -> None:
    path = "/firewall/rules/ipv4"
    origin = router.get(f"{BASE}{path}").mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil.example/steal"})
    )
    target = router.get("https://evil.example/steal").mock(
        return_value=httpx.Response(200, json={"stolen": True})
    )
    client = make_client()
    try:
        with pytest.raises(SophosAPIError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    assert info.value.status == 302
    assert origin.call_count == 1
    assert target.call_count == 0
    assert_no_key(info.value)


async def test_trust_env_is_disabled(router: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:3128")

    path = "/network/dns/protection/status"
    route = router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json={}))
    client = make_client()
    try:
        assert client._client._trust_env is False  # type: ignore[attr-defined]
        assert client._client.follow_redirects is False
        await client.get(path)
    finally:
        await client.aclose()

    assert str(route.calls.last.request.url) == f"{BASE}{path}"


# -- Transport construction --------------------------------------------------


async def test_transport_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    real_client = httpx.AsyncClient

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        captured.update(kwargs)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    client = make_client()
    try:
        assert captured["base_url"] == BASE
        assert captured["headers"] == {
            "Authorization": f"Bearer {KEY}",
            "Accept": "application/json",
        }
        assert captured["verify"] is True
        assert captured["timeout"] == httpx.Timeout(30.0)
        assert captured["follow_redirects"] is False
        assert captured["trust_env"] is False
    finally:
        await client.aclose()


async def test_ca_bundle_is_passed_to_httpx(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ca_bundle = tmp_path / "sophos-ca.pem"
    ca_bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")

    captured: dict[str, Any] = {}

    class RecordingAsyncClient:
        """Capture the constructor kwargs without loading the (fake) CA file."""

        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(httpx, "AsyncClient", RecordingAsyncClient)
    client = make_client(SOPHOS_CA_BUNDLE=str(ca_bundle))
    try:
        assert captured["verify"] == str(ca_bundle)
    finally:
        await client.aclose()


async def test_verification_can_be_disabled_for_the_lab(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    real_client = httpx.AsyncClient

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        captured.update(kwargs)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    client = make_client(SOPHOS_VERIFY_SSL="false")
    try:
        assert captured["verify"] is False
    finally:
        await client.aclose()


async def test_timeout_comes_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    real_client = httpx.AsyncClient

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        captured.update(kwargs)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    client = make_client(SOPHOS_TIMEOUT="12.5")
    try:
        assert captured["timeout"] == httpx.Timeout(12.5)
    finally:
        await client.aclose()


async def test_ipv6_host_is_bracketed_in_the_request_url(router: Any) -> None:
    settings = Settings.from_env({"SOPHOS_HOST": "2001:db8::1", "SOPHOS_API_KEY": KEY})
    url = "https://[2001:db8::1]:4444/api/firewall-config/v1/network/dns/protection/status"
    route = router.get(url).mock(return_value=httpx.Response(200, json={}))
    client = SophosRestClient(settings)
    try:
        await client.get("/network/dns/protection/status")
    finally:
        await client.aclose()

    assert str(route.calls.last.request.url) == url


# -- Pagination --------------------------------------------------------------


async def test_get_page_defaults(router: Any) -> None:
    path = "/authentication/users"
    route = router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json=PAGE_BODY))
    client = make_client()
    try:
        result = await client.get_page(path)
    finally:
        await client.aclose()

    assert result == PAGE_BODY
    assert result["items"] == PAGE_BODY["items"]
    assert result["pages"] == PAGE_BODY["pages"]
    assert str(route.calls.last.request.url) == f"{BASE}{path}?page=1&pageSize=50&pageTotal=false"


async def test_get_page_custom_values_and_filters(router: Any) -> None:
    path = "/authentication/users"
    route = router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json=PAGE_BODY))
    client = make_client()
    try:
        result = await client.get_page(
            path, page=2, page_size=10, page_total=True, params={"nameContains": "adm"}
        )
    finally:
        await client.aclose()

    assert result == PAGE_BODY
    assert (
        str(route.calls.last.request.url)
        == f"{BASE}{path}?nameContains=adm&page=2&pageSize=10&pageTotal=true"
    )


async def test_get_page_accepts_the_maximum_page_size(router: Any) -> None:
    path = "/authentication/users"
    route = router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json=PAGE_BODY))
    client = make_client()
    try:
        await client.get_page(path, page_size=100)
    finally:
        await client.aclose()

    assert "pageSize=100" in str(route.calls.last.request.url)


@pytest.mark.parametrize(
    ("page", "page_size"),
    [(0, 50), (-1, 50), (1, 0), (1, 101), (1, -5), (1.5, 50), (True, 50), (1, True)],
)
async def test_get_page_validates_before_io(router: Any, page: Any, page_size: Any) -> None:
    catch_all = router.route().mock(return_value=httpx.Response(200, json=PAGE_BODY))
    client = make_client()
    try:
        with pytest.raises(ValueError):
            await client.get_page("/authentication/users", page=page, page_size=page_size)
    finally:
        await client.aclose()

    assert catch_all.call_count == 0


async def test_get_page_rejects_a_non_object_body(router: Any) -> None:
    path = "/authentication/users"
    router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    client = make_client()
    try:
        with pytest.raises(SophosAPIError) as info:
            await client.get_page(path)
    finally:
        await client.aclose()

    assert "non-object" in str(info.value)


async def test_get_page_rejects_missing_metadata(router: Any) -> None:
    path = "/authentication/users"
    router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json={"items": []}))
    client = make_client()
    try:
        with pytest.raises(SophosAPIError) as info:
            await client.get_page(path)
    finally:
        await client.aclose()

    assert "items" in str(info.value)
    assert "pages" in str(info.value)


# -- Lifecycle ---------------------------------------------------------------


async def test_aclose_is_idempotent() -> None:
    client = make_client()
    await client.aclose()
    await client.aclose()

    assert client._client.is_closed is True


async def test_async_context_manager_closes(router: Any) -> None:
    path = "/network/dns/protection/status"
    router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json={}))

    async with make_client() as client:
        assert await client.get(path) == {}
        assert client._client.is_closed is False

    assert client._client.is_closed is True


async def test_client_reuses_one_pool(router: Any) -> None:
    router.get(f"{BASE}/a").mock(return_value=httpx.Response(200, json={}))
    router.get(f"{BASE}/b").mock(return_value=httpx.Response(200, json={}))
    client = make_client()
    inner = client._client
    try:
        await client.get("/a")
        await client.get("/b")
        assert client._client is inner
        assert inner.is_closed is False
    finally:
        await client.aclose()


# -- Secret handling ---------------------------------------------------------


async def test_api_key_is_redacted_from_auth_errors(router: Any) -> None:
    path = "/firewall/rules/ipv4"
    router.get(f"{BASE}{path}").mock(
        return_value=httpx.Response(
            401, json={"error": "unauthenticated", "message": "Token missing or invalid."}
        )
    )
    client = make_client()
    try:
        with pytest.raises(SophosAuthError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    assert_no_key(info.value)


async def test_api_key_is_redacted_from_transport_errors(router: Any) -> None:
    path = "/network/dns/protection/status"
    router.get(f"{BASE}{path}").mock(side_effect=httpx.ConnectError(f"proxy rejected token {KEY}"))
    client = make_client()
    try:
        with pytest.raises(SophosTransportError) as info:
            await client.get(path)
    finally:
        await client.aclose()

    assert "[REDACTED]" in str(info.value)
    assert_no_key(info.value)


async def test_api_key_is_redacted_from_ambiguous_write_errors(router: Any) -> None:
    path = "/firewall/rules/ipv4"
    router.post(f"{BASE}{path}").mock(side_effect=httpx.ReadTimeout(f"timeout for {KEY}"))
    client = make_client()
    try:
        with pytest.raises(SophosAmbiguousWriteError) as info:
            await client.post(path, json={"name": "allow-lan"})
    finally:
        await client.aclose()

    assert "[REDACTED]" in str(info.value)
    assert_no_key(info.value)


async def test_client_repr_does_not_contain_the_key() -> None:
    client = make_client()
    try:
        assert KEY not in repr(client)
        assert BASE in repr(client)
    finally:
        await client.aclose()


def test_client_requires_settings() -> None:
    with pytest.raises(TypeError):
        SophosRestClient("https://fw.example.com")  # type: ignore[arg-type]
