# Examples

`sample-timeline.md` shows the report format with placeholder data (RFC 5737
documentation IPs, `example.*` names). Reading it like an analyst:

- **The `fim` high and the `persistence` phase** line up to the second with the admin's
  `sudo install … example-app.service`: one thread, entry → privilege → persistence.
  That is a deliberate deploy, so the response is to **re-baseline**, not to investigate.
- **The `dns` beaconing high** is an hourly check-in with near-perfect regularity. In
  practice this is often a legitimate agent (tunnel daemons, update checkers). Confirm
  the owning process with `conn_inventory`, then allowlist it or chase it.
- **Feeder coverage** is all `ok`. A `MISSING` row means a blind spot, never an all-clear.

Real cases contain host-identifying data (IPs, accounts, SSH key fingerprints, DNS
history). Don't publish them.
