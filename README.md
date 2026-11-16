# SysReptor Read-Only Proxy

API intermediária, em Docker, que expõe **apenas consulta** de projetos e findings
do SysReptor. O token real fica no container; a equipe recebe uma chave própria
que só funciona neste proxy.

## Subir

```bash
cp .env.example .env
openssl rand -hex 32          # gere a chave de consulta e cole em READONLY_API_KEYS
vi .env                       # preencha SYSREPTOR_URL e SYSREPTOR_API_TOKEN
docker compose up -d --build
```

## Endpoints (todos GET)

| Rota | Retorno |
|---|---|
| `/health` | status do proxy (sem autenticação) |
| `/projects` | lista de projetos (id, nome, tags, datas) |
| `/projects/{id}` | dados básicos de um projeto |
| `/projects/{id}/findings` | findings do projeto |
| `/projects/{id}/findings/{finding_id}` | um finding |
| `/findings` | todos os findings de todos os projetos |
| `/docs` | Swagger/OpenAPI |

Autenticação: `Authorization: Bearer <chave>` ou `X-API-Key: <chave>`.

```bash
curl -H "Authorization: Bearer $CHAVE" http://localhost:8080/projects
curl -H "Authorization: Bearer $CHAVE" http://localhost:8080/projects/<uuid>/findings
```

## Operação

- **Revogar/rotacionar chave:** edite `READONLY_API_KEYS` no `.env` e rode `docker compose up -d`.
- **Várias equipes:** `READONLY_API_KEYS=gestao-vulns:chaveA,soc:chaveB` — o nome aparece no log de cada consulta.
- **Limitar projetos:** `ALLOWED_PROJECT_IDS=<uuid1>,<uuid2>`.
- **HTTPS:** publique atrás de um reverse proxy com TLS (nginx, Caddy, Traefik); o container fala HTTP puro na 8080.
