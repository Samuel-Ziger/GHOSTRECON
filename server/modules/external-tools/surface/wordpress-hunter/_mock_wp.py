# -*- coding: utf-8 -*-
"""Servidor WordPress FALSO para testar o WPHunter localmente (autorizado)."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = """<!DOCTYPE html><html><head>
<meta name="generator" content="WordPress 5.2.1">
<link rel="stylesheet" href="/wp-content/themes/avada/style.css?ver=6.2.3">
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.1"></script>
</head><body>wp-content uploads wp-includes</body></html>"""

USERS = json.dumps([{"id":1,"name":"Administrador","slug":"admin",
                     "avatar_urls":{"96":"http://x/a.png"}},
                    {"id":2,"name":"Joao","slug":"joao","avatar_urls":{}}])

README_CF7 = "=== Contact Form 7 ===\nStable tag: 5.1\n"
STYLE_AVADA = "/*\nTheme Name: Avada\nVersion: 6.2.3\nAuthor: ThemeFusion\n*/"

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "Apache/2.4.41")
        self.send_header("X-Powered-By", "PHP/7.2.0")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        b = body.encode() if isinstance(body, str) else body
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        p = self.path
        if p in ("/", "/index.php"): return self._send(200, HOME)
        if p.startswith("/wp-json/wp/v2/users"): return self._send(200, USERS, "application/json")
        if p == "/wp-json/": return self._send(200, json.dumps({"name":"Teste","description":"d"}), "application/json")
        if p.startswith("/?author="):
            return self._send(301, "", extra={"Location":"/author/admin/"})
        if p == "/wp-content/plugins/contact-form-7/readme.txt": return self._send(200, README_CF7, "text/plain")
        if p == "/wp-content/themes/avada/style.css": return self._send(200, STYLE_AVADA, "text/css")
        if p == "/readme.html": return self._send(200, "<br />Version 5.2.1")
        if p == "/.env": return self._send(200, "DB_PASSWORD=secret123\nAPP_KEY=abc", "text/plain")
        if p == "/wp-content/uploads/": return self._send(200, "<title>Index of /uploads</title><h1>Index of</h1>Parent Directory")
        if p.startswith("/?s="):
            # vulnerável a XSS refletido
            from urllib.parse import unquote, parse_qs, urlparse
            q = parse_qs(urlparse(p).query).get("s", [""])[0]
            return self._send(200, f"<html>Resultados para: {q}</html>")
        if p == "/wp-login.php": return self._send(200, "<form id='loginform'>login</form>")
        if p == "/xmlrpc.php": return self._send(200, "XML-RPC server accepts POST requests only.")
        return self._send(404, "Not Found")
    def do_POST(self):
        if self.path == "/xmlrpc.php":
            resp = "<methodResponse><params><param><value><array><data>" \
                   "<value><string>system.multicall</string></value>" \
                   "<value><string>pingback.ping</string></value>" \
                   "</data></array></value></param></params></methodResponse>"
            return self._send(200, resp, "text/xml")
        if self.path == "/wp-login.php":
            return self._send(200, "<div id='login_error'>senha incorreta</div>")
        return self._send(404, "x")

if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 8899), H)
    print("Mock WP em http://127.0.0.1:8899")
    srv.serve_forever()
