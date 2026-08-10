# Culligan traffic interception rig

Everything runs from **LewisDesktop**. mitmproxy 12.2.3 is installed in `..\venv`.
The CA was generated during setup and lives in `conf\mitmproxy-ca-cert.pem`.

There are two independent things worth intercepting, and they answer different
questions:

| Track | Target | Answers |
|---|---|---|
| 1 | The **phone app** | What the cloud API looks like, and whether the app ever talks locally |
| 2 | The **softener itself** | What the device↔cloud protocol is, where control commands actually live |

Track 1 is easier. Track 2 is more valuable. Do 1 first.

---

## Track 1 — intercept the Culligan Connect app

### Start the proxy

```bash
cd D:\PersonalProjects\culligan-local
venv\Scripts\mitmdump.exe -s mitm\culligan_addon.py --set confdir=mitm\conf
```

Listens on `:8080`. Output appears in `mitm\capture\`:

- `flows.jsonl` — raw capture. **Contains live auth tokens. Treat as a password file.**
- `api-summary.md` — deduplicated endpoint inventory, redacted, safe to share.
- `LOCAL-HITS.txt` — only written if the app talks to a private IP. Redacted, safe to share.

Reports rewrite continuously, so Ctrl+C never loses them.

### Getting the phone to trust the proxy

This is the only hard part. Android 7+ ignores user-installed CAs for app traffic
unless the app opts in, and the app may also pin certificates. Try these in order —
don't jump to the complex one until the simple one fails.

**Option A — plain proxy + user CA (5 minutes, might just work)**

1. Allow inbound 8080 through Windows Firewall.
2. Phone → Wi-Fi → modify network → Manual proxy → desktop's LAN IP, port 8080.
3. Browse to `http://mitm.it` on the phone, install the Android cert.
4. Open Culligan Connect.

If flows appear in `api-summary.md`, you're done. If the app fails to connect or
shows network errors, it's rejecting the user CA — go to B.

**Option B — WireGuard mode (better, and catches non-HTTP traffic)**

```bash
venv\Scripts\mitmdump.exe --mode wireguard -s mitm\culligan_addon.py --set confdir=mitm\conf
```

This prints a QR code. Install the WireGuard app on the phone, scan it, connect.
All phone traffic now routes through the desktop — including MQTT or raw TCP that
an HTTP proxy would never see. You still need the CA installed for TLS, so this
solves routing, not pinning.

**Option C — Android emulator on the desktop (most reliable, no phone at all)**

Install Android Studio, then create an AVD with these constraints:

- API level **30–33** (not 34+ — system certs moved into an APEX container and the
  remount trick stops working)
- **"Google APIs"** image, *not* "Google Play" — Play images are production-signed
  and refuse `adb root`, which makes the whole approach impossible

Then install the CA into the **system** store, which defeats the user-CA
restriction entirely:

```bash
emulator -avd <name> -writable-system -http-proxy 127.0.0.1:8080
adb root && adb remount
openssl x509 -inform PEM -subject_hash_old -in mitm\conf\mitmproxy-ca-cert.pem
# take the 8-hex-digit hash from line 1, then:
adb push mitm\conf\mitmproxy-ca-cert.pem /system/etc/security/cacerts/<hash>.0
adb shell chmod 644 /system/etc/security/cacerts/<hash>.0
adb reboot
```

Sideload the Culligan Connect APK and run it. If it *still* fails, the app is doing
genuine certificate pinning — at that point run the APK through `apk-mitm`, or attach
Frida with a pinning-bypass script.

### What to look for

- **Any entry in `LOCAL-HITS.txt`.** This is the whole reason we're here. It means
  the app reached the softener directly and local control is real.
- The base host. `uniapi.culliganiot.com` means the newer proprietary backend;
  anything `*.aylanetworks.com` means the older Ayla stack.
- The **write** calls specifically — whatever fires when you toggle bypass or start a
  regeneration. Reads are easy and already solved upstream; control is the open problem.

---

## Track 2 — intercept the softener itself

More valuable, because device↔cloud is where control commands actually live, and it
sidesteps the app's pinning entirely.

The softener won't trust our CA — but plenty of IoT devices don't validate
certificates properly, and it costs nothing to find out. If it accepts our cert, we
see everything.

Rough shape:

1. Point the softener at the desktop as its gateway/DNS (a static DHCP reservation
   plus a DNS override for the Culligan hostname is the least invasive way).
2. Run mitmproxy in transparent mode.
3. Watch whether TLS completes or the device hangs up.

If it hangs up, that's a cert-validation failure and this track is closed without
firmware work. If it completes, this becomes the main line of the project.

Worth doing right after Track 1 — it's a short test with a large payoff.

---

## Note on MQTT

If the app or device uses MQTT (port 8883) rather than HTTPS, the HTTP-proxy modes
won't decode it. WireGuard or transparent mode will still *capture* the TCP stream,
but you'll get bytes rather than parsed messages. Say so if that's what shows up and
the addon can be extended to frame MQTT packets.
