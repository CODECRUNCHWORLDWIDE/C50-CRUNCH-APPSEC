# Exercise 1 — Provision the Isolated Lab

**Goal:** Stand up the Docker-based, no-egress-in lab from Lecture 3, with all three vulnerable targets running, and **prove** — not assume — that it's isolated before you touch anything in Exercise 2.

**Estimated time:** 90 minutes.

## Before you start

Confirm the basics work:

```bash
docker --version
docker run hello-world
```

If either fails, install/fix Docker first (see [`resources.md`](../resources.md)) — nothing else in this course works without it.

## Task 1 — Write `lab-setup.sh`

Create a script that builds the whole lab from nothing, in one run. This is the script you'll re-run every week this course reuses the lab.

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "Creating isolated network..."
docker network create appsec-lab || echo "  (network already exists, continuing)"

echo "Starting OWASP Juice Shop on 127.0.0.1:3000 ..."
docker run -d --name juice-shop --network appsec-lab \
  -p 127.0.0.1:3000:3000 bkimminich/juice-shop

echo "Starting DVWA on 127.0.0.1:3001 ..."
docker run -d --name dvwa --network appsec-lab \
  -p 127.0.0.1:3001:80 vulnerables/web-dvwa

echo "Starting OWASP WebGoat on 127.0.0.1:3002 ..."
docker run -d --name webgoat --network appsec-lab \
  -p 127.0.0.1:3002:8080 webgoat/webgoat

echo "Waiting 15s for services to finish booting..."
sleep 15

echo "Lab containers:"
docker ps --filter network=appsec-lab
```

Make it executable and run it:

```bash
chmod +x lab-setup.sh
./lab-setup.sh
```

## Task 2 — Confirm each target loads

Visit each in a browser and confirm it renders:

- `http://127.0.0.1:3000` — Juice Shop storefront.
- `http://127.0.0.1:3001/setup.php` — click **Create / Reset Database**, then log in at `http://127.0.0.1:3001/login.php` with `admin` / `password`.
- `http://127.0.0.1:3002/WebGoat` — create a WebGoat account (any username/password — it's a local, isolated instance) and confirm the lesson menu loads.

## Task 3 — Verify isolation is real (do not skip)

Run through Lecture 3, Section 5, precisely. Record your results in `isolation-check.md`:

1. **From your own machine**, confirm all three targets load at their `127.0.0.1` URLs.
2. **From a second device on your home network** (a phone on the same Wi-Fi is easiest), find your machine's LAN IP (`ifconfig`/`ipconfig`) and try `http://<your-LAN-IP>:3000` from that second device's browser. **This must fail to connect.**
3. If step 2 *succeeds* from the other device, your ports are published to `0.0.0.0` instead of `127.0.0.1`. Fix it: `docker rm -f juice-shop dvwa webgoat`, edit `lab-setup.sh` to make sure every `-p` flag reads `127.0.0.1:PORT:PORT`, and re-run.

In `isolation-check.md`, record: the exact command/URL you tried for each check, and the result (pass/fail), for all three targets.

## Task 4 — Snapshot your commands, not the containers

Unlike VM snapshots, your "reset" for this lab is destroy-and-recreate from `lab-setup.sh`. Add a `lab-teardown.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
docker rm -f juice-shop dvwa webgoat 2>/dev/null || true
docker network rm appsec-lab 2>/dev/null || true
echo "Lab torn down."
```

Test the full cycle once: `./lab-teardown.sh` then `./lab-setup.sh` again, and confirm all three targets come back up clean.

## Expected result (spot checks)

- `docker ps --filter network=appsec-lab` shows exactly 3 running containers.
- All three URLs load from your own machine.
- The LAN-IP check from a second device **fails to connect** for all three ports.
- `lab-teardown.sh` followed by `lab-setup.sh` rebuilds a working lab from nothing.

## Done when…

- [ ] `lab-setup.sh` and `lab-teardown.sh` exist, are executable, and both run cleanly.
- [ ] `isolation-check.md` documents all three isolation checks with pass/fail results.
- [ ] You can explain, in one sentence, why `-p 127.0.0.1:3000:3000` and `-p 3000:3000` are not the same thing.
- [ ] All three targets (Juice Shop, DVWA, WebGoat) load and you've logged into DVWA and created a WebGoat account.

## Stretch

- Add a `docker-compose.yml` that starts all three targets with one `docker compose up -d`, replacing the three separate `docker run` calls in `lab-setup.sh`.
- Add a fourth verification: from inside one target container (`docker exec -it juice-shop sh`), confirm you can reach the *other* lab containers by name on the Docker network but get no meaningful response attempting to reach a real external host beyond what the container needed at startup.

## Submission

Commit `lab-setup.sh`, `lab-teardown.sh`, and `isolation-check.md` to your portfolio under `c50-week-01/exercise-01/`. You'll reuse `lab-setup.sh` unmodified for the rest of this course.
