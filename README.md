# Hyundai OTA Security Simulator

A live demo of the cryptographic core of a UNECE R156 Software Update
Management System (SUMS) -- the regulation that makes secure OTA update
delivery a legal precondition for vehicle type approval in 60+ countries.
Grounded directly in Hyundai's real Bluelink OTA infrastructure, which
just shipped a security-relevant remote-immobilizer feature via C-OTA
update (rolling out through 2026).

This is a running system you attack, not a slide about cryptography: a
real FastAPI OTA server managing signed firmware campaigns for a simulated
fleet, real vehicle clients that verify signatures before installing
anything, and three attack scripts that try (and fail) to defeat it.

## The three attacks, and why each one fails

| Attack | What the attacker has | Why it's rejected |
|---|---|---|
| `rogue_key_attack.py` | Their own valid Ed25519 keypair, a plausible-looking fake update | The vehicle only trusts the ONE public key pinned at manufacture time -- a signature from any other key fails verification, full stop |
| `tampered_firmware_attack.py` | A genuine, correctly-signed package, intercepted in transit and altered by one byte | The signature was computed over the original bytes; any tampering, however small, breaks it |
| `downgrade_attack.py` | An OLD firmware version that is 100% genuinely signed by the manufacturer | A valid signature isn't enough -- the vehicle also enforces that any offered version must be strictly newer than what it's running, so a forced rollback to a known-vulnerable build is rejected even though every cryptographic check on the package itself passes |

The third one is the subtle, important lesson: **signature verification
alone does not stop a downgrade attack.** You need monotonic version
enforcement as a separate, independent control.

## Also modeled: legitimate rollback (not an attack)

Unrelated to the attacks above, UNECE R156 also requires the ability to
*revert* a bad update. `fleet_sim/vehicle_client.py` runs a simulated
post-install health check after every real install; if it fails (modeling
a genuinely buggy build, publishable with `--buggy`), the vehicle reverts
to its previous known-good version and reports a `rolled_back` event --
this is the system working correctly, not a defense catching an attacker.

## Running it

```bash
pip install -r requirements.txt
python scripts/setup_keys.py          # generates the manufacturer Ed25519 keypair
uvicorn ota_server.main:app --port 8100
```

In another terminal, live dashboard:

```bash
open http://localhost:8100/admin/dashboard
```

Legitimate flow:

```bash
python fleet_sim/run_fleet.py                                            # fleet checks in, no campaign yet
python scripts/publish_firmware.py --version 1.0.0 --model Ioniq5 --regions US-West,US-East,EU-DE,EU-FR
python fleet_sim/run_fleet.py                                            # installs the factory baseline
python scripts/publish_firmware.py --version 2.0.0 --model Ioniq5 --regions US-West,US-East,EU-DE,EU-FR
python fleet_sim/run_fleet.py                                            # a real campaign rolls out
```

A buggy build that triggers real rollbacks:

```bash
python scripts/publish_firmware.py --version 2.1.0 --model Ioniq5 --regions US-West,US-East,EU-DE,EU-FR --buggy
python fleet_sim/run_fleet.py --fail-rate 0.5
```

The three attacks (run after at least one campaign has been published):

```bash
python attack_simulator/rogue_key_attack.py
python attack_simulator/tampered_firmware_attack.py
python attack_simulator/downgrade_attack.py --old-version 1.0.0
```

Watch `/admin/dashboard` while these run: fleet firmware version
distribution, rejected-update reasons, and a live event log, updating
every 2 seconds.

## Project layout

```
ota_server/
  main.py         FastAPI: admin publish, vehicle check-in/download/report, dashboard
  crypto.py        Ed25519 signing/verification, SHA-256 integrity hashing
  store.py         in-memory fleet/firmware/event state
  versioning.py    monotonic version comparison (anti-downgrade)
  templates/       dashboard HTML
fleet_sim/
  vehicle_client.py   the vehicle-side defense logic (this is the important file)
  run_fleet.py         registers + polls the simulated fleet
attack_simulator/
  rogue_key_attack.py
  tampered_firmware_attack.py
  downgrade_attack.py
scripts/
  setup_keys.py       generates the manufacturer keypair
  publish_firmware.py legitimate sign-and-publish flow
```

## What I'd do differently in production

- The private key belongs in an HSM, never a file on the server's disk.
- Firmware would be delivered from a CDN with the OTA server only issuing
  signed manifests, not serving the bytes directly.
- Add rate limiting and anomaly detection on `/ota/check-in` itself
  (a fleet of check-ins from one source is its own signal, same idea as
  the bot-defense layer in `fashion-catalog-guard`).
- Persist the event log; right now it's in-memory and resets on restart.
