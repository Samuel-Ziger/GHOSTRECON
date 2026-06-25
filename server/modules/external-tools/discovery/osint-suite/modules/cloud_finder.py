"""
modules/cloud_finder.py — Descobre buckets S3/Azure/GCS expostos
"""

import itertools
from core.base import BaseModule

PERMUTATIONS = [
    "{t}", "{t}-backup", "{t}-prod", "{t}-dev", "{t}-staging", "{t}-data",
    "{t}-assets", "{t}-static", "{t}-files", "{t}-media", "{t}-uploads",
    "{t}-logs", "{t}-archive", "{t}-public", "{t}-private", "{t}-storage",
    "{t}-bucket", "{t}-s3", "{t}-cdn", "{t}-images", "{t}-db", "{t}-database",
    "backup-{t}", "prod-{t}", "dev-{t}", "staging-{t}", "data-{t}",
    "assets-{t}", "static-{t}", "files-{t}", "media-{t}",
]

SENSITIVE_EXTENSIONS = [
    ".env", ".sql", ".bak", ".dump", ".tar.gz", ".zip",
    ".pem", ".key", ".p12", ".pfx", ".csv", ".xls", ".xlsx",
    "credentials", "secret", "password", "passwd", "config",
]


class CloudFinder(BaseModule):
    name        = "CloudFinder"
    description = "Descobre buckets S3/Azure/GCS expostos publicamente"

    def run(self, target: str) -> dict:
        # Normaliza: remove www., extensão de domínio
        base = target.lower().replace("www.", "").split(".")[0]
        self.info(f"Enumerando buckets para: [bold]{base}[/bold]")

        names    = [p.format(t=base) for p in PERMUTATIONS]
        s3       = self._check_s3(names)
        azure    = self._check_azure(names)
        gcs      = self._check_gcs(names)

        total_exposed = len(s3["exposed"]) + len(azure["exposed"]) + len(gcs["exposed"])
        self.success(f"{total_exposed} buckets expostos encontrados")

        return {
            "target": target,
            "base":   base,
            "s3":     s3,
            "azure":  azure,
            "gcs":    gcs,
        }

    def _check_s3(self, names: list) -> dict:
        exposed = []
        for name in names:
            url  = f"https://{name}.s3.amazonaws.com/"
            resp = self.get(url)
            if resp and resp.status_code == 200:
                files    = self._list_s3_files(resp.text)
                sensitivo = [f for f in files if any(s in f.lower() for s in SENSITIVE_EXTENSIONS)]
                exposed.append({
                    "bucket":    name,
                    "url":       url,
                    "files":     files[:20],
                    "sensitive": sensitivo,
                })
                self.warn(f"S3 exposto: {name}")
        return {"provider": "AWS S3", "checked": len(names), "exposed": exposed}

    def _check_azure(self, names: list) -> dict:
        exposed = []
        for name in names:
            url  = f"https://{name}.blob.core.windows.net/?comp=list"
            resp = self.get(url)
            if resp and resp.status_code == 200 and "<EnumerationResults" in resp.text:
                exposed.append({"container": name, "url": url})
                self.warn(f"Azure Blob exposto: {name}")
        return {"provider": "Azure Blob", "checked": len(names), "exposed": exposed}

    def _check_gcs(self, names: list) -> dict:
        exposed = []
        for name in names:
            url  = f"https://storage.googleapis.com/{name}/"
            resp = self.get(url)
            if resp and resp.status_code == 200:
                exposed.append({"bucket": name, "url": url})
                self.warn(f"GCS exposto: {name}")
        return {"provider": "Google Cloud Storage", "checked": len(names), "exposed": exposed}

    def _list_s3_files(self, xml_text: str) -> list:
        import re
        return re.findall(r"<Key>([^<]+)</Key>", xml_text)
