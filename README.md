# IoT protocol tools

Small, dependency-light tools for working out how an undocumented IoT device
talks to its cloud — built while reverse-engineering a Culligan water softener,
but none of them are Culligan-specific.

The integration that came out of this work lives separately at
[ha-culligan-azure](https://github.com/heidrickla/ha-culligan-azure).

## What's here

| Tool | Does |
|---|---|
| `recon.py` | Sweeps a subnet, flags Espressif-OUI hosts, probes for an Ayla-style local HTTP API |
| `parse_capture.py` | Pulls DNS query names and TLS SNI out of a `tcpdump` capture. Stdlib only — no scapy, no tshark |
| `dnsproxy.py` | Logging DNS forwarder. Observe-only by default; can answer chosen names with your own address |
| `tlsprobe.py` | TLS listener that logs the SNI **even when the client rejects the certificate** |
| `mitm/culligan_addon.py` | mitmproxy addon that turns captured traffic into an API inventory |
| `send_command.py` | Sends a documented device command. Dry-run by default |
| `set_device_time.py` | Sets the softener's controller clock — something the vendor app has no UI for |
| `watch_commands.py` | Reports each new command verb as it appears in a capture |

## The one that mattered

`tlsprobe.py` is the tool that actually solved it. A device's TLS ClientHello
carries the **SNI in plaintext**, before the client has had any chance to reject
your certificate. So even against a device that validates its chain properly —
and this one did, which killed every impersonation approach — you still learn
exactly which host it wanted. That single fact identified the endpoint after
hours of dead ends.

The corollary is worth internalising: **a failed handshake is not a failed
measurement.**

## Notes from the work

Things that cost real time and might save yours:

- **A reading of zero usually means your instrument isn't looking.** Six separate
  times a measurement said "nothing there" when the truth was "not measuring
  it": a display filter that dropped falsy values, a lifetime counter mistaken
  for a current one, an LED assumed to mean one thing that meant another, a
  firewall rule shadowed by a broader rule above it, `protocol=all` combined
  with a port group so it matched nothing, and a cached DNS answer. Every one
  was caught by a control or a cross-check. **None** by re-reading the
  instrument.
- **Check whether the thing already reports before building something to
  measure it.** The endpoint hostname we spent hours inferring was being logged
  in plain text by the network gateway the whole time.
- **Single-connection devices exist**, and contention presents as a *hang*, not a
  refusal — which looks identical to a crashed device. Close every other client
  before concluding anything is broken.
- **Don't trust `expiresIn`.** One API here advertised 3600 seconds and rejected
  the token after ~27 minutes. Re-authenticate reactively on 401.

## Scope and intent

These are diagnostic tools for hardware **you own**, on a network **you
control**. Intercepting traffic you are not authorised to intercept is a
different activity with a different legal status, and nothing here is designed
for it — `dnsproxy.py` defaults to observe-only, `send_command.py` and
`set_device_time.py` default to dry runs, and all of them expect you to already
have credentials for the account in question.

No capture output, credentials, keys, or vendor binaries are in this repository,
and the `.gitignore` is written to keep it that way — everything these tools
*produce* is sensitive.

## License

GPL-3.0 — see [LICENSE](LICENSE).
