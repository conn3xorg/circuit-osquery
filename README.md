# circuit-osquery

[![Conn3x grade](https://conn3x.org/circuits/osquery/grade.svg)](https://conn3x.org/circuits/osquery/grade)

A Conn3x circuit that installs osquery from osquery's own apt and yum repositories and runs `osqueryd` as a systemd service, with `osquery.conf` built from your inputs: options, scheduled queries, query packs and file integrity monitoring. Results go to JSON log files on the host, which osquery rotates itself, and the circuit checks every config with `osqueryd --config_check` before it restarts the daemon.

osquery turns a Linux host into a set of tables you can query with SQL: users, processes, listening ports, installed packages, changed files. It's the host half of a detection lab like DetectionLab, where osquery feeds a Fleet server. This circuit can point osqueryd at a Fleet server you already run, too; setting up Fleet itself isn't part of it.

## Usage

```hcl
module "osquery" {
  source = "github.com/conn3xorg/circuit-osquery?ref=v0.2.1"

  hosts                = { web = "192.168.1.50" }
  ssh_private_key_file = "~/.ssh/id_ed25519"

  schedule = {
    listening_ports = { query = "SELECT pid, port, address FROM listening_ports;", interval = 300 }
    users           = { query = "SELECT username, uid, shell FROM users;", interval = 3600, snapshot = true }
  }

  packs = ["incident-response", "ossec-rootkit"]

  file_paths = {
    etc      = ["/etc/%%"]
    binaries = ["/usr/bin/%", "/usr/sbin/%"]
  }
}
```

Then run `conn3x init` and `conn3x apply`. A second `conn3x plan` says `No changes.` Within a few minutes, results show up on the host:

```sh
tail -f /var/log/osquery/osqueryd.results.log
osqueryi --json "SELECT version FROM osquery_info"
```

For hosts created in the same plan, pass host objects with the host key you generated, so Conn3x checks it without a known_hosts entry. Give each one's distribution in `os` too: the circuit picks its repository by distribution, and Conn3x can't ask a host that doesn't exist yet. If `os` turns out not to match the host, Conn3x stops before configuring it. Set `os` as well when you put `depends_on` on this module: `depends_on` holds back reading the hosts until the apply, so without `os` the plan fails with `Invalid for_each argument`.

```hcl
hosts = {
  for name, d in digitalocean_droplet.web : name => {
    address  = d.ipv4_address
    host_key = tls_private_key.host[name].public_key_openssh
    os       = "ubuntu"
  }
}
```

To try it on a throwaway container first, see [examples/local](examples/local).

### Scheduled queries and packs

Each entry in `schedule` runs its query every `interval` seconds. By default osquery logs what changed since the last run, as `added` and `removed` rows, to `osqueryd.results.log`. With `snapshot = true` it logs the whole result every time, to `osqueryd.snapshots.log` instead.

`packs` turns on packs osquery ships in `/opt/osquery/share/osquery/packs`, by name. The ones that do something on Linux are `hardware-monitoring`, `incident-response`, `it-compliance`, `osquery-monitoring`, `ossec-rootkit` and `vuln-management`. `custom_packs` writes packs of your own into the config: a set of queries shaped like `schedule`, with an optional `platform` and `discovery` queries that must all return rows for the pack to run.

```hcl
custom_packs = {
  listening = {
    platform = "linux"
    queries = {
      ports = { query = "SELECT pid, port, protocol, address FROM listening_ports;", interval = 60 }
    }
  }
}
```

### File integrity monitoring

`file_paths` lists paths to watch, by category. `%` matches anything in one directory and `%%` matches recursively, so `/etc/%%` is everything under `/etc`. When it's set, the circuit turns on osquery's file events with `--disable_events=false` and `--enable_file_events=true`, and schedules `SELECT * FROM file_events;` every `file_events_interval` seconds, so each change lands in the results log with its path, action and hashes. A `file_events` entry in `schedule` replaces that query.

osquery watches with inotify. A recursive path over a big tree uses one watch per directory, so keep the paths to what you care about.

### Logs

osqueryd writes JSON lines with the filesystem logger to `/var/log/osquery`: `osqueryd.results.log` and `osqueryd.snapshots.log`. When one reaches `log_rotate_size` bytes, osquery rotates it, compresses the old ones with zstd and keeps `log_rotate_max_files` of them. Point a log shipper at those two files to get the results off the host.

osqueryd's own status log, `osqueryd.INFO.*`, starts a new small file at each start and isn't part of that rotation.

### Fleet

Set `fleet` and `enroll_secret` to enroll the hosts with a [Fleet](https://fleetdm.com) server you already run:

```hcl
variable "fleet_enroll_secret" {
  type      = string
  ephemeral = true
  sensitive = true
}

module "osquery" {
  # ...
  fleet = {
    address      = "fleet.example.com:8080"
    server_certs = "/etc/osquery/fleet.pem"
  }
  enroll_secret = var.fleet_enroll_secret
}
```

The circuit writes the enroll secret to `/etc/osquery/enroll_secret`, mode `0600`, and never through state or the plan. Every plan needs it too, since Conn3x checks the file on the host against it. It adds Fleet's TLS flags to the flags file: enroll, config, distributed queries and logging, against the endpoints Fleet documents for plain osquery. `server_certs` is a CA bundle that's already on the host, such as one you put there with a `file` step; leave it out when Fleet has a certificate from a public CA.

With Fleet set, Fleet supplies the config, so the local `osquery.conf`, with your schedule, packs and file paths, isn't read. Manage those in Fleet. Results go to Fleet and stay in the local log as well. Remove `fleet` and the next apply deletes the secret and goes back to the local config.

This was checked against a Fleet address that doesn't exist: the flags, the secret file and the daemon came up, and osqueryd kept retrying its enrollment. Enrollment with a real Fleet server hasn't been tested. A circuit for Fleet itself may come later.

## What it does

On each host, in order:

1. Adds osquery's repository with its signing key: `https://pkg.osquery.io/deb`, suite `deb`, on Debian and Ubuntu, and `https://pkg.osquery.io/rpm/$basearch` on the Red Hat family. The key, `1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B`, is in `files/osquery.asc`. It has no expiry date.
2. Installs `osquery` at `osquery_version`. A higher version upgrades it in place.
3. With `fleet`, writes `enroll_secret` to `/etc/osquery/enroll_secret`, mode `0600`.
4. Writes `/etc/osquery/osquery.flags`, mode `0600`, with the logger, rotation, file events and Fleet flags, and `/etc/osquery/osquery.conf`, mode `0600`, with `options`, the schedule, the packs and `file_paths`. These are the two files the package's `osqueryd.service` reads. The circuit owns both.
5. Runs `osqueryd --config_check` against both files, with a scratch database so it doesn't fight the running daemon for its lock. A config osquery can't parse, an unknown option or a pack it can't read fails the apply here, and the running daemon carries on with what it had. It doesn't check the SQL: a query on a table that doesn't exist only shows up in osqueryd's log.
6. Restarts `osqueryd` when the package, the flags, the config or the secret changed, and starts it at boot.

### What it doesn't do

- It doesn't set up Fleet, or any other server. Getting the logs off the host is up to a log shipper or Fleet.
- It doesn't turn on audit-based tables such as `process_events` or `socket_events`. They need the audit subsystem, which other tools on the host may already use.
- It doesn't take arbitrary command-line flags. `options` covers what osquery reads from the config.
- It doesn't set `exclude_paths` for file integrity monitoring, and it doesn't load osquery extensions.
- Deleting the module leaves osquery installed and running with the last config.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `hosts` | any | Required | Hosts to configure, by name. Each value is an address, such as `"203.0.113.10"`, or a host object such as `{ address = "203.0.113.10", host_key = "ssh-ed25519 AAAA..." }`. A host object can also set `user`, `port`, `private_key_file`, `jump_hosts` and `os`, the distribution's ID, such as `ubuntu` or `rocky`, which a host created in the same plan needs. The two forms can be mixed. |
| `ssh_user` | string | `"root"` | User to log in as. |
| `ssh_port` | number | `22` | SSH port. |
| `ssh_private_key_file` | string | `null` | Path to a private key. When null, Conn3x uses the SSH agent. |
| `ssh_known_hosts_file` | string | `null` | known_hosts file to check host keys against. When null, `~/.ssh/known_hosts`. Not used for a host object with `host_key`. |
| `ssh_become` | bool | `false` | Run commands as root through sudo. Set it when `ssh_user` isn't root. |
| `osquery_version` | string | `"5.24.0"` | osquery release to install. Raising it upgrades in place. |
| `options` | map(string) | `{}` | The config's `options`, such as `{ schedule_splay_percent = "10", host_identifier = "uuid" }`. The logger, config plugin, events, TLS, enroll and distributed flags aren't allowed: the circuit sets those in the flags file. |
| `schedule` | map(object) | `{}` | Scheduled queries, by name. Each has `query`, `interval` in seconds, and optionally `snapshot` (default `false`). |
| `packs` | list(string) | `[]` | Packs osquery ships, by name, such as `["incident-response"]`. |
| `custom_packs` | map(object) | `{}` | Packs of your own, by name. Each has `queries`, shaped like `schedule`, and optionally `platform` and `discovery`. |
| `file_paths` | map(list(string)) | `{}` | Paths to watch for file integrity monitoring, by category, such as `{ etc = ["/etc/%%"] }`. |
| `file_events_interval` | number | `300` | Seconds between runs of the `file_events` query, when `file_paths` is set. |
| `log_rotate_size` | number | `26214400` | Size in bytes at which osquery rotates its results and snapshots logs. 25 MiB by default. |
| `log_rotate_max_files` | number | `25` | Rotated logs osquery keeps of each kind. |
| `fleet` | object | `null` | A Fleet server to enroll with: `address`, such as `"fleet.example.com:8080"`, and optionally `server_certs`, a CA bundle's path on the host, `host_identifier` (default `"uuid"`), `config_refresh` and `distributed_interval` in seconds (default `10` each). |
| `enroll_secret` | string | `null` | Fleet's enroll secret. Required with `fleet`. Ephemeral and sensitive: pass it with `-var` or `TF_VAR_`. |

## Outputs

| Name | Description |
| --- | --- |
| `config_file` | Path of the osquery config on each host, `/etc/osquery/osquery.conf`. |
| `flags_file` | Path of the osquery flags file on each host, `/etc/osquery/osquery.flags`. |
| `results_log` | Path of the results log on each host, `/var/log/osquery/osqueryd.results.log`. |

## Requirements

Requires Conn3x v0.6.9 or later and systemd on each host, with outbound HTTPS to pkg.osquery.io. amd64 and arm64. The package's service caps osqueryd at 20% of one CPU, and the droplets it was tested on had 1 GB of memory.

## Tested on

Rocky Linux 10, Fedora 45, Ubuntu 24.04 and Debian 13, with osquery 5.24.0. [examples/local](examples/local) was applied to each on arm64, and the second plan had no changes. On each, `osqueryd` was running, the 10-second `os_version` query reached `osqueryd.results.log` and a file touched under `/etc` showed up there from `file_events` within 30 seconds, and `osqueryi --json "SELECT version FROM osquery_info"` answered. CI runs the same checks on amd64. On Rocky Linux 10, an unknown option failed the apply at the check, before the restart, a 1 KB `log_rotate_size` rotated and compressed the logs, and `fleet` with a made-up address wrote the secret file with mode `0600`, kept it out of state, and left osqueryd running and retrying its enrollment.

CI also restarts the container and checks osqueryd comes back and logs a new file change. It applies with a Fleet address no server answers on and a random enroll secret, checks the secret is in `/etc/osquery/enroll_secret` with mode `0600` and nowhere in `terraform.tfstate`, then applies without `fleet` and checks the file is gone and logging works again. On a fresh container it installs osquery 5.23.1, then applies the circuit's own pin over it, and checks the second plan is empty, `osquery_info` reports 5.24.0 and the logging checks pass.

On an Ubuntu 24.04 droplet and a Rocky Linux 10 droplet with SELinux enforcing, both `s-1vcpu-1gb`, the example's inputs applied, the same checks passed, and after a reboot osqueryd was running, a new file change was logged and the plan was clean. On Rocky Linux osqueryd runs as `unconfined_service_t`, and the audit log had no denials.

## License

MPL-2.0. See [LICENSE](LICENSE). osquery itself is Apache-2.0 or GPL-2.0.
