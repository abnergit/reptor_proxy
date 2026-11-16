"""
SysReptor Read-Only Proxy
-------------------------
API intermediária que expõe SOMENTE consulta de projetos e findings do SysReptor.

- O token real do SysReptor fica apenas neste container (variável de ambiente).
- Os consumidores usam chaves próprias (READONLY_API_KEYS), que só valem aqui.
- Só existem rotas GET, e os caminhos chamados no SysReptor são fixos no código:
  nada do que o cliente envia é repassado, exceto UUIDs validados.
"""
import hashlib
import hmac
import logging
import os
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("sysreptor-ro-proxy")


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Variável de ambiente obrigatória ausente: {name}")
    return value


SYSREPTOR_URL = _required("SYSREPTOR_URL").rstrip("/")
SYSREPTOR_TOKEN = _required("SYSREPTOR_API_TOKEN")
VERIFY_TLS = os.getenv("SYSREPTOR_VERIFY_TLS", "true").lower() not in ("false", "0", "no")
MAX_PAGES = int(os.getenv("MAX_PAGES", "200"))

# Formato: "nome1:chave1,nome2:chave2" (o nome aparece só no log) ou apenas "chave1,chave2"
API_KEYS: dict[str, str] = {}
for i, item in enumerate(filter(None, (p.strip() for p in _required("READONLY_API_KEYS").split(",")))):
    name, sep, key = item.partition(":")
    if not sep:
        name, key = f"key{i + 1}", item
    if len(key) < 32:
        raise RuntimeError(f"A chave '{name}' tem menos de 32 caracteres. Gere com: openssl rand -hex 32")
    API_KEYS[name] = key

# Opcional: restringe a consulta a projetos específicos (UUIDs separados por vírgula)
ALLOWED_PROJECTS = {
    str(UUID(p.strip())) for p in os.getenv("ALLOWED_PROJECT_IDS", "").split(",") if p.strip()
}

PROJECT_FIELDS = ("id", "name", "tags", "language", "readonly", "created", "updated", "project_type")
FINDING_FIELDS = ("id", "created", "updated", "status", "order", "template", "data")

app = FastAPI(
    title="SysReptor Read-Only Proxy",
    description="Consulta (somente leitura) de projetos e findings do SysReptor.",
    version="1.0.0",
    redoc_url=None,
)
client = httpx.AsyncClient(
    base_url=SYSREPTOR_URL,
    headers={"Authorization": f"Bearer {SYSREPTOR_TOKEN}", "Accept": "application/json"},
    verify=VERIFY_TLS,
    timeout=30,
    follow_redirects=False,
)


@app.on_event("shutdown")
async def _shutdown() -> None:
    await client.aclose()


# ---------------------------------------------------------------- autenticação
def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


async def auth(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
) -> str:
    presented = x_api_key
    if not presented and authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    matched = None
    if presented:
        d = _digest(presented)
        for name, key in API_KEYS.items():  # compara com todas (tempo constante)
            if hmac.compare_digest(d, _digest(key)):
                matched = name
    if not matched:
        raise HTTPException(401, "Chave de API inválida ou ausente",
                            headers={"WWW-Authenticate": "Bearer"})
    return matched


# ------------------------------------------------------------------- upstream
async def upstream_get(path: str, params: Optional[dict] = None) -> Any:
    try:
        r = await client.get(path, params=params)
    except httpx.HTTPError as exc:
        log.error("Falha ao contatar o SysReptor: %s", type(exc).__name__)
        raise HTTPException(502, "Falha ao contatar o SysReptor")
    if r.status_code == 404:
        raise HTTPException(404, "Não encontrado")
    if r.status_code != 200:
        log.error("SysReptor respondeu HTTP %s em %s", r.status_code, path)
        raise HTTPException(502, f"SysReptor respondeu HTTP {r.status_code}")
    return r.json()


async def upstream_list(path: str, params: Optional[dict] = None) -> list:
    """Lê listas do SysReptor, seguindo a paginação por cursor quando houver."""
    params = dict(params or {})
    items: list = []
    for _ in range(MAX_PAGES):
        data = await upstream_get(path, params)
        if isinstance(data, list):
            return data
        items.extend(data.get("results", []))
        nxt = data.get("next")
        if not nxt:
            break
        # Reaproveita apenas o cursor; nunca segue a URL devolvida pelo servidor.
        cursor = parse_qs(urlparse(nxt).query).get("cursor", [None])[0]
        if not cursor:
            break
        params["cursor"] = cursor
    return items


def pick(obj: dict, fields: tuple) -> dict:
    return {k: obj.get(k) for k in fields if k in obj}


def check_project(project_id: UUID) -> str:
    pid = str(project_id)
    if ALLOWED_PROJECTS and pid not in ALLOWED_PROJECTS:
        raise HTTPException(404, "Não encontrado")
    return pid


# ---------------------------------------------------------------------- rotas
@app.get("/health", tags=["infra"])
async def health() -> dict:
    return {"status": "ok"}


@app.get("/projects", tags=["consulta"])
async def list_projects(who: str = Depends(auth)) -> list:
    """Lista projetos (ativos e finalizados) visíveis para o token do SysReptor."""
    seen: dict[str, dict] = {}
    for readonly in ("false", "true"):
        for p in await upstream_list("/api/v1/pentestprojects/", {"readonly": readonly}):
            seen[p["id"]] = pick(p, PROJECT_FIELDS)
    projects = [p for p in seen.values() if not ALLOWED_PROJECTS or p["id"] in ALLOWED_PROJECTS]
    log.info("client=%s GET /projects -> %d", who, len(projects))
    return projects


@app.get("/projects/{project_id}", tags=["consulta"])
async def get_project(project_id: UUID, who: str = Depends(auth)) -> dict:
    pid = check_project(project_id)
    p = await upstream_get(f"/api/v1/pentestprojects/{pid}/")
    log.info("client=%s GET /projects/%s", who, pid)
    return pick(p, PROJECT_FIELDS)


@app.get("/projects/{project_id}/findings", tags=["consulta"])
async def list_findings(project_id: UUID, who: str = Depends(auth)) -> list:
    """Findings do projeto. O conteúdo (título, CVSS, descrição...) vem em `data`."""
    pid = check_project(project_id)
    findings = await upstream_list(f"/api/v1/pentestprojects/{pid}/findings/")
    findings.sort(key=lambda f: f.get("order") or 0)
    log.info("client=%s GET /projects/%s/findings -> %d", who, pid, len(findings))
    return [pick(f, FINDING_FIELDS) for f in findings]


@app.get("/projects/{project_id}/findings/{finding_id}", tags=["consulta"])
async def get_finding(project_id: UUID, finding_id: UUID, who: str = Depends(auth)) -> dict:
    pid = check_project(project_id)
    f = await upstream_get(f"/api/v1/pentestprojects/{pid}/findings/{finding_id}/")
    log.info("client=%s GET /projects/%s/findings/%s", who, pid, finding_id)
    return pick(f, FINDING_FIELDS)


@app.get("/findings", tags=["consulta"])
async def all_findings(who: str = Depends(auth)) -> list:
    """Todos os findings de todos os projetos permitidos, com o projeto de origem."""
    out = []
    for p in await list_projects(who):
        for f in await upstream_list(f"/api/v1/pentestprojects/{p['id']}/findings/"):
            out.append({"project_id": p["id"], "project_name": p.get("name"), **pick(f, FINDING_FIELDS)})
    log.info("client=%s GET /findings -> %d", who, len(out))
    return out
