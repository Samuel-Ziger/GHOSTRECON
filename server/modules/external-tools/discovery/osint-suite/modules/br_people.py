"""
modules/br_people.py — OSINT em fontes abertas brasileiras
AVISO: Apenas consulta dados PÚBLICOS. Respeita a LGPD.
"""

import re
from bs4 import BeautifulSoup
from core.base import BaseModule

CNPJ_RE   = re.compile(r"\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}")
CPF_CLEAN = re.compile(r"[^\d]")


class BRPeopleOSINT(BaseModule):
    name        = "BRPeopleOSINT"
    description = "OSINT em fontes abertas brasileiras (CNPJ, Diário Oficial, etc.)"

    def run(self, target: str) -> dict:
        self.info(f"Consultando fontes brasileiras para: [bold]{target}[/bold]")
        results = {}

        # Detecta tipo de target
        if CNPJ_RE.match(target.replace(" ", "")):
            cnpj = re.sub(r"[^\d]", "", target)
            results["cnpj"]    = self._consulta_cnpj(cnpj)
            results["simples"] = self._consulta_simples(cnpj)
        else:
            # Busca por nome/empresa
            results["receita"]       = self._busca_receita_nome(target)
            results["diario_oficial"] = self._busca_diario_oficial(target)
            results["jusbrasil"]     = self._busca_jusbrasil(target)
            results["linkedin_br"]   = self._busca_linkedin_publico(target)

        return {"target": target, **results}

    # ------------------------------------------------------------------
    def _consulta_cnpj(self, cnpj: str) -> dict:
        """API pública da Receita Federal via ReceitaWS."""
        url  = f"https://www.receitaws.com.br/v1/cnpj/{cnpj}"
        resp = self.get(url, headers={"Accept": "application/json"})
        if resp:
            try:
                data = resp.json()
                if data.get("status") == "ERROR":
                    return {"error": data.get("message")}
                return {
                    "razao_social":  data.get("nome"),
                    "fantasia":      data.get("fantasia"),
                    "situacao":      data.get("situacao"),
                    "atividade":     data.get("atividade_principal", [{}])[0].get("text"),
                    "abertura":      data.get("abertura"),
                    "porte":         data.get("porte"),
                    "natureza":      data.get("natureza_juridica"),
                    "capital_social":data.get("capital_social"),
                    "email":         data.get("email"),
                    "telefone":      data.get("telefone"),
                    "endereco": {
                        "logradouro": data.get("logradouro"),
                        "numero":     data.get("numero"),
                        "municipio":  data.get("municipio"),
                        "uf":         data.get("uf"),
                        "cep":        data.get("cep"),
                    },
                    "socios": [
                        {"nome": s.get("nome"), "qual": s.get("qual")}
                        for s in data.get("qsa", [])
                    ],
                }
            except Exception as e:
                return {"error": str(e)}
        return {"error": "Sem resposta"}

    def _consulta_simples(self, cnpj: str) -> dict:
        """Verifica opção pelo Simples Nacional via API pública."""
        url  = f"https://www.receitaws.com.br/v1/cnpj/{cnpj}/integrais"
        resp = self.get(url)
        if resp:
            try:
                data = resp.json()
                return {
                    "optante_simples":   data.get("optante_simples_nacional"),
                    "optante_mei":       data.get("optante_mei"),
                    "situacao_simples":  data.get("situacao_simples"),
                }
            except Exception:
                pass
        return {}

    def _busca_receita_nome(self, nome: str) -> list:
        """Busca empresas por nome na API da Receita (CNPJA)."""
        url  = f"https://cnpja.com/office/search?query={nome}&limit=5"
        resp = self.get(url)
        if resp:
            try:
                data = resp.json()
                return [
                    {
                        "cnpj":    e.get("taxId"),
                        "nome":    e.get("alias") or e.get("company", {}).get("name"),
                        "uf":      e.get("address", {}).get("state"),
                        "status":  e.get("status", {}).get("text"),
                    }
                    for e in data.get("data", [])
                ]
            except Exception:
                pass
        return []

    def _busca_diario_oficial(self, target: str) -> list:
        """Scraping passivo do Portal de Diários Oficiais (SIGA)."""
        url  = f"https://www.in.gov.br/consulta/-/buscar/dou?q={target}&s=todos&exactDate=personalizado&startDate=&endDate=&sortType=0"
        resp = self.get(url)
        results = []
        if resp:
            soup = BeautifulSoup(resp.text, "html.parser")
            for item in soup.select(".resultado-item")[:5]:
                title = item.select_one("h5")
                date  = item.select_one(".date-result")
                link  = item.select_one("a")
                if title:
                    results.append({
                        "titulo": title.get_text(strip=True),
                        "data":   date.get_text(strip=True) if date else "",
                        "url":    "https://www.in.gov.br" + link["href"] if link else "",
                    })
        return results

    def _busca_jusbrasil(self, target: str) -> list:
        """Scraping passivo de processos no JusBrasil."""
        url  = f"https://www.jusbrasil.com.br/consulta-processual/busca?q={target}"
        resp = self.get(url)
        results = []
        if resp:
            soup = BeautifulSoup(resp.text, "html.parser")
            for item in soup.select(".SearchResult")[:5]:
                title = item.select_one(".title")
                desc  = item.select_one(".description")
                link  = item.select_one("a")
                if title:
                    results.append({
                        "processo": title.get_text(strip=True),
                        "resumo":   desc.get_text(strip=True)[:200] if desc else "",
                        "url":      link["href"] if link else "",
                    })
        return results

    def _busca_linkedin_publico(self, target: str) -> list:
        """Busca perfis LinkedIn públicos via Google (sem autenticação)."""
        query = f'site:linkedin.com/in "{target}" Brasil'
        url   = f"https://www.google.com/search?q={query}&num=5"
        resp  = self.get(url, headers={"User-Agent": "Mozilla/5.0"})
        results = []
        if resp:
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.select("a"):
                href = a.get("href", "")
                if "linkedin.com/in/" in href:
                    results.append({"url": href, "texto": a.get_text(strip=True)[:80]})
        return results[:5]
