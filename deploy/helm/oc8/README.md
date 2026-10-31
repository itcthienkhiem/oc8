# oc8 Helm chart

Install the **Community Edition** stack on Kubernetes — the same components as
`docker compose up`: Postgres (pgvector), Redis, migrate, backend, worker,
ingestion-worker, scheduler, frontend, and Caddy as edge proxy.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.10+
- **Container images** built from this repository (see below)
- A default `StorageClass` for Postgres and session PVCs (or set `storageClassName`)

## Build images (from repo root)

```bash
docker build -f Dockerfile.backend -t oc8-backend:latest ./backend
docker build -t oc8-frontend:latest ./frontend
```

Push to your registry and set `images.backend.repository` / `images.frontend.repository`
in `values.yaml`, or load into kind/minikube:

```bash
kind load docker-image oc8-backend:latest oc8-frontend:latest
```

## Generate secrets

```bash
export OC8_JWT_SECRET=$(openssl rand -hex 32)
export OC8_SECRET_KEK=$(openssl rand -base64 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)
```

## Install

From the repository root:

```bash
helm upgrade --install oc8 ./deploy/helm/oc8 \
  --namespace oc8 --create-namespace \
  --set secrets.jwtSecret="$OC8_JWT_SECRET" \
  --set secrets.secretKek="$OC8_SECRET_KEK" \
  --set secrets.postgresPassword="$POSTGRES_PASSWORD"   --set secrets.redisPassword="$(openssl rand -hex 32)"
```

### Capas (tool packs)

The Compose stack bind-mounts `./capas`. In Kubernetes you must provide the capas
tree explicitly:

**Option A — hostPath (local clusters / kind):**

```bash
helm upgrade --install oc8 ./deploy/helm/oc8 \
  ... \
  --set backend.capas.hostPath=/path/on/node/to/oc8/capas
```

**Option B — PVC** populated by your own init job or CI, then:

```yaml
backend:
  capas:
    existingClaim: oc8-capas
```

### Local models (Ollama)

```bash
helm upgrade --install oc8 ./deploy/helm/oc8 \
  ... \
  --set ollama.enabled=true
```

Then pull a model into the Ollama pod and select it in **Settings → Models**.

### Agent sandboxes (Docker-out-of-Docker)

Off by default. Enabling mounts the container runtime socket — **root-equivalent**
on the node. Only for dedicated test clusters:

```yaml
backend:
  containerSocket:
    enabled: true
oc8:
  agentIsolation: true
```

## Configuration

| Value | Purpose |
|-------|---------|
| `secrets.*` | Required JWT, KEK, Postgres password |
| `oc8.env` | `prod` (default) or `dev` — `dev` enables unauthenticated dev-login; never on a reachable cluster |
| `oc8.seedOnStart` | Seed demo tenant on first migrate (default `false`) |
| `worker.replicas` | Scale workers (default `2`) |
| `caddy.service.type` | `LoadBalancer` (default), `NodePort`, or `ClusterIP` |
| `ingress.enabled` | Use Ingress instead of Caddy (set `caddy.enabled: false`) |
| `ollama.enabled` | Bundled Ollama StatefulSet |

See `values.yaml` for the full list.

## Upgrade

```bash
helm upgrade oc8 ./deploy/helm/oc8 -n oc8 -f my-values.yaml
```

The backend init container runs `alembic upgrade head` on each backend pod start.
Keep `backend.replicas: 1` unless you externalise migrations.

## Uninstall

```bash
helm uninstall oc8 -n oc8
```

Postgres and session PVCs are retained unless you delete them manually.

## Publishing the chart

When `charts.oc8.io` is live:

```bash
helm package deploy/helm/oc8
helm repo index .
```

Until then, install from the git checkout path as shown above.

## Related

- [Docker Compose deploy](../../../docs/DEPLOY.md)
- [Quickstart](../../../docs/user/quickstart.md)
