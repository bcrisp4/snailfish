# Self-host a Snailfish relay

This guide sets up a relay on one Linux host with Docker Compose. Caddy terminates TLS in front of the relay. The relay stores only ciphertext.

The relay serves 1 to 5 users. One small host with 1 vCPU and 1 GB of memory is enough (DESIGN.md "SLOs").

## Before you start

You need:

- A Linux host with a public IP address, and ports 80 and 443 open to the internet.
- Docker Engine 24 or later with the Compose plugin.
- Git.
- A domain name, for example `sync.example.net`. A passkey works only on its domain, so the domain must stay the same.
- A DNS A or AAAA record of that domain that points to the host.

The relay can also run behind `tailscale serve` on a Tailscale `ts.net` name. This guide uses Caddy and a public domain.

## Install

1. Clone the repository on the host.

   ```bash
   git clone https://github.com/bcrisp4/snailfish.git
   cd snailfish/ops/compose
   ```

2. Copy the example settings to `.env`.

   ```bash
   cp env.example .env
   ```

3. In `.env`, set `SNAILFISH_DOMAIN` to your domain and `SNAILFISH_ACME_EMAIL` to your email address.
4. Build the relay image and start the relay and Caddy.

   ```bash
   docker compose up -d --build
   ```

   The first build takes about 10 minutes, because it builds a static binary with a vendored OpenSSL.

5. Check the health route through Caddy. The answer is `{"status":"ok"}`.

   ```bash
   curl https://sync.example.net/v1/health
   ```

   If `curl` reports a certificate error, read the Caddy log with `docker compose logs caddy`. Caddy needs ports 80 and 443 and the DNS record to get a certificate.

## Add a user

1. Create the user and its invite link.

   ```bash
   docker compose exec relay snailfish-relay user add sam
   ```

2. Send the link to the user over a private channel. The link works once and expires after 7 days.
3. The user opens the link in a browser and registers a passkey.
4. The user signs in to the app on each device. The app opens the relay sign-in page in the system browser.

If a user loses every passkey, make a new link. The new link removes the old passkeys and browser sessions of that user.

```bash
docker compose exec relay snailfish-relay user invite sam
```

A sign-in page tells a caller whether a user name has a passkey. The rate limit slows a search for names. Use user names that are not public.

## Quotas

The relay limits the stored change bytes of each space and the number of spaces of each user. `.env` sets the defaults for all users: `SNAILFISH_SPACE_BYTES` (256 MiB) and `SNAILFISH_MAX_SPACES` (32).

To set other values for one user, run the `quota` command. A value that you do not give goes back to the default.

```bash
docker compose exec relay snailfish-relay quota sam --space-bytes 536870912
```

At a full quota, the relay refuses new changes and serves the stored changes. The app shows `paused: quota`.

## Monitoring

The relay serves metrics in the Prometheus text format on `127.0.0.1:9464` of the host, at `/metrics`. Caddy does not forward this port.

1. Add a scrape job to Prometheus for `127.0.0.1:9464`.
2. Add `ops/prometheus/snailfish.rules.yml` to the `rule_files` of Prometheus.
3. Add a blackbox exporter probe of `https://<your domain>/v1/health` every 5 minutes, with the job name `snailfish-health`.
4. Route the alerts with Alertmanager.

The rules alert on these conditions:

| Alert | Condition |
| --- | --- |
| `SnailfishDown` | 3 failed health probes in a row |
| `SnailfishHigh5xxRate` | More than 5% of responses are 5xx for 15 minutes |
| `SnailfishSpaceAboveQuota` | A space uses more than 95% of its quota |
| `SnailfishSpaceAboveReserve` | A space uses more than 50% of its security record reserve |
| `SnailfishSpaceManyStubs` | A space holds more than 1 million stubs |
| `SnailfishDiskFull` | Less than 10% of the data file system is free |
| `SnailfishStorageError`, `SnailfishMigrationFailed` | A storage error or a failed schema migration |

The metrics hold no tenant handle, log ID or device ID. The storage figure of each tenant carries the user name.

## Back up and restore

The backup holds ciphertext, public keys, passkey public keys and user webhook URLs. A webhook URL can hold a secret, so keep each backup private. The backup does not hold `session.key`.

1. Make a backup while the relay runs.

   ```bash
   docker compose exec relay snailfish-relay backup /data/backups/2026-11-06
   ```

2. Copy the backup off the host.

   ```bash
   docker compose cp relay:/data/backups/2026-11-06 ./2026-11-06
   ```

3. Delete the copy inside the data volume. The relay image has no shell, so use a `busybox` container.

   ```bash
   docker run --rm -v snailfish_data:/data busybox rm -rf /data/backups/2026-11-06
   ```

To restore a backup from the directory `./2026-11-06`:

1. Stop the relay.

   ```bash
   docker compose stop relay
   ```

2. Restore the backup over the data.

   ```bash
   docker compose run --rm -v "$PWD/2026-11-06:/restore:ro" relay restore --replace /restore
   ```

3. Start the relay.

   ```bash
   docker compose start relay
   ```

A restore puts each space on a restore hold. Each device repairs the log from its own copy at its next sync. The user releases each hold on the user page. On a new host, each user signs in again in the browser, because the host has a new `session.key`.

## Delete a space

A trusted device deletes its space from the app. If no device can do it, delete the space with its log ID. The user page lists the log ID of each space.

```bash
docker compose exec relay snailfish-relay space delete sam l_00112233445566778899aabbccddeeff
```

The relay keeps a deletion marker for the log ID, and refuses a new space with that log ID. Each device keeps its data. An import from a device makes the space again.

The user page also downloads the export file of each space. The file holds only envelopes and stubs. With the file and the recovery key, a new device makes the space again on any relay.

## Move to another relay

1. Set up the new relay with this guide.
2. Add the user on the new relay.
3. On one device, import the space into the new relay from the app.
4. On each other device, sign in to the new relay from the app.
5. Delete the space on the old relay.

## Upgrade

1. Make a backup.
2. Get the new release.

   ```bash
   git fetch --tags
   git checkout <release tag>
   ```

3. Build and start the new image.

   ```bash
   docker compose up -d --build
   ```

4. Check the health route.

Upgrade the relay before the apps. A relay accepts requests from older engines.

## Logs

The relay writes no request logs. Its log holds error classes only. Caddy writes no access log with `ops/proxy/Caddyfile`. Read the logs with `docker compose logs`.

`ops/proxy/nginx.conf` is a sample for nginx in place of Caddy.
