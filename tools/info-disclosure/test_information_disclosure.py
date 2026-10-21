import contextlib
import importlib.util
import io
import pathlib
import types
import unittest
from requests.packages.urllib3.exceptions import ProtocolError


MODULE_PATH = pathlib.Path(__file__).with_name("information_disclosure.py")
SPEC = importlib.util.spec_from_file_location("ghostrecon_info_disclosure", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeResponse:
    def __init__(self, text):
        self.text = text


def make_hunter():
    args = types.SimpleNamespace(
        user_agent="ghostrecon-test",
        proxy=None,
        insecure=False,
        timeout=1,
        delay=0,
    )
    return MODULE.InfoHunter("https://example.test", args)


class ErrorDifferentialTests(unittest.TestCase):
    def test_baseline_signature_is_not_reported_again(self):
        hunter = make_hunter()
        hunter._req = lambda _url: FakeResponse("Traceback (most recent call last): baseline")
        with contextlib.redirect_stdout(io.StringIO()):
            hunter._probe_errors("https://example.test/api")
        self.assertEqual(hunter.findings, [])

    def test_only_new_signature_is_reported_and_payloads_are_generic(self):
        hunter = make_hunter()
        calls = []

        def request(url):
            calls.append(url)
            if "infohunter=" not in url:
                return FakeResponse("normal response")
            return FakeResponse('Traceback (most recent call last): File "app.py", line 7')

        hunter._req = request
        with contextlib.redirect_stdout(io.StringIO()):
            hunter._probe_errors("https://example.test/api")
        self.assertEqual(len(hunter.findings), 1)
        self.assertIn("induced_new_signature=true", hunter.findings[0]["evidencia"])
        self.assertFalse(any("../" in url or "AND%20" in url for url in calls))


class ResponseLifecycleTests(unittest.TestCase):
    def test_protocol_error_closes_response_and_returns_unavailable(self):
        hunter = make_hunter()
        closed = []

        def broken_read(*_args, **_kwargs):
            raise ProtocolError("fixture truncated stream")

        response = types.SimpleNamespace(
            raw=types.SimpleNamespace(read=broken_read),
            close=lambda: closed.append(True),
        )
        hunter.session = types.SimpleNamespace(request=lambda *_a, **_kw: response)
        self.assertIsNone(hunter._req("/fixture"))
        self.assertEqual(closed, [True])

    def test_response_is_bounded_and_closed_on_success(self):
        hunter = make_hunter()
        closed = []
        response = types.SimpleNamespace(
            raw=types.SimpleNamespace(read=lambda *_a, **_kw: b"x" * (MODULE.MAX_RESPONSE_BYTES + 1)),
            close=lambda: closed.append(True),
        )
        hunter.session = types.SimpleNamespace(request=lambda *_a, **_kw: response)
        result = hunter._req("/fixture")
        self.assertEqual(len(result._content), MODULE.MAX_RESPONSE_BYTES)
        self.assertTrue(result.ghostrecon_truncated)
        self.assertEqual(closed, [True])

    def test_unexpected_reader_exception_still_closes_response(self):
        hunter = make_hunter()
        closed = []

        def broken_read(*_args, **_kwargs):
            raise ValueError("fixture reader error")

        response = types.SimpleNamespace(
            raw=types.SimpleNamespace(read=broken_read),
            close=lambda: closed.append(True),
        )
        hunter.session = types.SimpleNamespace(request=lambda *_a, **_kw: response)
        with self.assertRaises(ValueError):
            hunter._req("/fixture")
        self.assertEqual(closed, [True])


if __name__ == "__main__":
    unittest.main()
