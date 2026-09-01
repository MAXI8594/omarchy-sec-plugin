# Omarchy Sec — bar widget

A Quickshell bar widget for [Omarchy](https://omarchy.org) that shows whether an
endpoint security sensor is actually running on this machine, and opens a panel
to inspect each one.

It detects Wazuh, CrowdStrike Falcon, Cortex XDR, SentinelOne, Microsoft
Defender (mdatp), Falco/Tetragon and auditd, and colours a shield in the bar:

| State | Meaning |
| :--- | :--- |
| Accent | At least one sensor is active |
| Urgent | No sensor is active — this endpoint is unprotected |
| Muted | Unknown — the `omarchy-sec` CLI is not installed, so nothing was measured |

The muted state matters: a security indicator that reports "unprotected" when it
simply could not look is a false alarm, so the widget says it does not know.

## Requirements

The widget is a thin front end. The detection itself lives in the **`omarchy-sec`
CLI**, which is packaged separately and must be installed for the widget to
report anything:

* `omarchy-sec-detect` — emits the sensor state as JSON
* `omarchy-sec agent` — hands a live incident to the Omarchy AI agent

See <https://github.com/MAXI8594/omarchy-sec>.

`xdg-open` (from `xdg-utils`) is used to open vendor consoles and the local
dashboard.

## Installation

```bash
omarchy plugin add https://github.com/MAXI8594/omarchy-sec-plugin.git --enable
```

`--enable` asks which bar section to place it in; the widget defaults to the
right side. To place it later, or after adding without `--enable`:

```bash
omarchy plugin enable io.github.maxi8594.omarchy-sec right
```

## Removal

```bash
omarchy plugin disable io.github.maxi8594.omarchy-sec
omarchy plugin remove  io.github.maxi8594.omarchy-sec
```

`remove` deletes the plugin folder from `~/.config/omarchy/plugins/`. The widget
writes nothing outside that folder, so nothing else is left behind — it never
touches `/usr/share/omarchy/`, and `omarchy update` is unaffected.

## Settings

Configurable from the widget's settings in the Omarchy shell:

| Key | Default | Notes |
| :--- | :--- | :--- |
| `dashboardUrl` | `https://localhost:9001` | Opened on middle-click and from the panel |
| `refreshIntervalSec` | `30` | 5–300. Each poll spawns the detector, which shells out to `systemctl` and `docker` — keep it coarse |
| `enableNotifications` | `true` | Desktop notifications for new alerts |

## Usage

* **Click** — open the panel, with a row per sensor
* **Middle-click** — open the SOC dashboard
* **Call Agent** (in the panel) — dispatch the current incident to the AI agent

## License

MIT — see [LICENSE](LICENSE).
