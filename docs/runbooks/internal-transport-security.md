# Internal Transport Security

Production internal service traffic should be protected by TLS, ideally mTLS (service mesh or reverse proxy).

## Runtime enforcement switch

- Set `ENFORCE_HTTPS_INTERNAL=true` in production to require `https://` internal base URLs.
- Services fail fast on non-HTTPS internal URLs when this flag is enabled.

## Recommendation

- Prefer mTLS between internal services (sidecar proxy or service mesh).
- If mesh is unavailable, terminate and re-encrypt with a trusted internal proxy tier.

## Caddy example (internal mTLS)

```caddy
{
  servers {
    protocol {
      experimental_http3
    }
  }
}

https://did-service.internal:3001 {
  tls /etc/certs/server.crt /etc/certs/server.key {
    client_auth {
      mode require_and_verify
      trusted_ca_cert_file /etc/certs/ca.crt
    }
  }
  reverse_proxy 127.0.0.1:3001
}
```

## NGINX example (internal mTLS)

```nginx
server {
  listen 443 ssl;
  server_name issuer-service.internal;

  ssl_certificate           /etc/certs/server.crt;
  ssl_certificate_key       /etc/certs/server.key;
  ssl_client_certificate    /etc/certs/ca.crt;
  ssl_verify_client         on;

  location / {
    proxy_pass http://127.0.0.1:3002;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}
```

## Deployment checklist

- Internal service DNS names resolve only inside private network.
- Certificates are rotated on a defined schedule.
- Service identities are unique per service/workload.
- Public ingress exposes only `app-gateway`.
