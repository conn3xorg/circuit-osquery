# Facts give each host's distribution, which picks osquery's apt or yum
# repository.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = try(each.value.os, self.os_id) == self.os_id
      error_message = "Host ${each.key} is ${self.os_id}, not the ${try(each.value.os, "")} its os says."
    }
  }
}

locals {
  # A host object's os stands in for the facts of a host created in the
  # same plan, which can't be read until it exists.
  os     = { for name, h in var.hosts : name => try(h.os, data.conn3x_host.facts[name].os_id) }
  family = { for name, o in local.os : name => contains(["debian", "ubuntu"], o) ? "debian" : "redhat" }

  # The paths osqueryd.service passes on its command line, from
  # /etc/default/osqueryd or /etc/sysconfig/osqueryd.
  config_file = "/etc/osquery/osquery.conf"
  flags_file  = "/etc/osquery/osquery.flags"
  secret_file = "/etc/osquery/enroll_secret"
  log_dir     = "/var/log/osquery"
  packs_dir   = "/opt/osquery/share/osquery/packs"

  fim = length(var.file_paths) > 0

  # file_events only reaches the log when a scheduled query reads it. A
  # file_events entry in var.schedule replaces this one.
  schedule = merge(
    local.fim ? { file_events = { query = "SELECT * FROM file_events;", interval = var.file_events_interval, snapshot = false } } : {},
    var.schedule,
  )

  config = jsonencode(merge(
    { options = var.options },
    { schedule = { for name, q in local.schedule : name => merge({ query = q.query, interval = q.interval }, q.snapshot ? { snapshot = true } : {}) } },
    length(var.packs) + length(var.custom_packs) == 0 ? {} : {
      packs = merge(
        { for p in var.packs : p => "${local.packs_dir}/${p}.conf" },
        { for name, p in var.custom_packs : name => merge(
          { queries = { for qn, q in p.queries : qn => merge({ query = q.query, interval = q.interval }, q.snapshot ? { snapshot = true } : {}) } },
          p.platform == null ? {} : { platform = p.platform },
          p.discovery == null ? {} : { discovery = p.discovery },
        ) },
      )
    },
    local.fim ? { file_paths = var.file_paths } : {},
  ))

  # Logger, events and Fleet settings only take effect at startup, so they
  # go in the flags file rather than the config's options. With Fleet,
  # results also stay in the local log, so they're on the host when Fleet
  # can't be reached.
  flags = join("\n", concat(
    [
      "# Written by Conn3x. Changes here are overwritten on the next apply.",
      "--logger_plugin=${var.fleet == null ? "filesystem" : "filesystem,tls"}",
      "--logger_path=${local.log_dir}",
      "--logger_rotate=true",
      "--logger_rotate_size=${var.log_rotate_size}",
      "--logger_rotate_max_files=${var.log_rotate_max_files}",
    ],
    local.fim ? ["--disable_events=false", "--enable_file_events=true"] : [],
    var.fleet == null ? [] : concat(
      [
        "--tls_hostname=${var.fleet.address}",
        "--enroll_secret_path=${local.secret_file}",
        "--host_identifier=${var.fleet.host_identifier}",
        "--enroll_tls_endpoint=/api/osquery/enroll",
        "--config_plugin=tls",
        "--config_tls_endpoint=/api/osquery/config",
        "--config_refresh=${var.fleet.config_refresh}",
        "--disable_distributed=false",
        "--distributed_plugin=tls",
        "--distributed_interval=${var.fleet.distributed_interval}",
        "--distributed_tls_max_attempts=3",
        "--distributed_tls_read_endpoint=/api/osquery/distributed/read",
        "--distributed_tls_write_endpoint=/api/osquery/distributed/write",
        "--logger_tls_endpoint=/api/osquery/log",
        "--logger_tls_period=10",
      ],
      var.fleet.server_certs == null ? [] : ["--tls_server_certs=${var.fleet.server_certs}"],
    ),
    [""],
  ))
}

circuit "osquery" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # One repository serves every release, for Debian and Ubuntu in one apt
  # suite and for the whole Red Hat family in one yum repository. Both are
  # signed with the same key, which has no expiry date.
  step "repo" {
    repository {
      name   = "osquery"
      url    = local.family[each.key] == "debian" ? "https://pkg.osquery.io/deb" : "https://pkg.osquery.io/rpm/$basearch"
      key    = file("${path.module}/files/osquery.asc")
      suites = local.family[each.key] == "debian" ? ["deb"] : null
    }
  }

  # apt only installs a version given in full, release included, and
  # osquery's packages all carry the same one.
  step "package" {
    package {
      name    = "osquery"
      version = "${var.osquery_version}-1.linux"
    }
  }

  # The secret lands in a file, never in state or the plan.
  step "enroll_secret" {
    for_each = toset(var.fleet == null ? [] : ["fleet"])
    file {
      path       = local.secret_file
      content_wo = var.enroll_secret
      mode       = "0600"
      on_remove  = "delete"
    }
  }

  step "flags" {
    file {
      path    = local.flags_file
      content = local.flags
      mode    = "0600"
    }
  }

  step "config" {
    file {
      path    = local.config_file
      content = local.config
      mode    = "0600"
    }
  }

  # osqueryd reads the flags and the config, packs included, as it would
  # at start, so a config it can't parse fails the apply before the
  # restart, and the running daemon keeps what it had. It only warns about
  # an unknown option or a pack it can't read, so those fail here too. The
  # check uses a database of its own, since the running daemon holds a lock
  # on its one, and the local config, so it doesn't reach out to Fleet. It
  # doesn't check the SQL: a query on a table that doesn't exist only shows
  # up in osqueryd's log.
  step "check" {
    command {
      command = "d=$(mktemp -d) && out=$(osqueryd --flagfile ${local.flags_file} --config_plugin=filesystem --config_path ${local.config_file} --database_path \"$d/db\" --pidfile \"$d/pid\" --disable_extensions --config_check 2>&1); rc=$?; rm -rf \"$d\"; if [ $rc -ne 0 ] || printf '%s\\n' \"$out\" | grep -qE 'unknown or invalid flag|Error reading the query pack'; then printf '%s\\n' \"$out\" >&2; exit 1; fi"
      triggers = {
        flags  = conn3x_file.osquery__flags[each.key].revision
        config = conn3x_file.osquery__config[each.key].revision
      }
    }
  }

  # osqueryd reads its flags and config only at start. It runs here rather
  # than in a handler, so a restart follows the check above in the same
  # apply. On the first apply it's what starts osqueryd.
  step "restart" {
    command {
      command = "systemctl restart osqueryd"
      triggers = {
        package = conn3x_package.osquery__package[each.key].revision
        check   = conn3x_command.osquery__check[each.key].revision
        secret  = try(conn3x_file.osquery__enroll_secret["${each.key}/fleet"].revision, "")
      }
    }
  }

  step "running" {
    service {
      name    = "osqueryd"
      state   = "started"
      enabled = true
    }
  }
}
