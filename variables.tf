variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file, jump_hosts or os."

  validation {
    condition     = alltrue([for h in var.hosts : contains(["debian", "ubuntu", "rocky", "almalinux", "rhel", "fedora"], try(h.os, "debian"))])
    error_message = "A host object's os must be one of debian, ubuntu, rocky, almalinux, rhel or fedora. CentOS Linux reached end of life on 30 June 2024: use Rocky Linux."
  }
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}


variable "osquery_version" {
  type        = string
  default     = "5.24.0"
  description = "osquery release to install, such as \"5.24.0\". Raising it upgrades osquery in place."

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.osquery_version))
    error_message = "osquery_version must be a full release, such as \"5.24.0\"."
  }
}

variable "options" {
  type        = map(string)
  default     = {}
  description = "osquery options for the config's options section, such as { schedule_splay_percent = \"10\", host_identifier = \"uuid\" }."

  # These are startup flags the circuit sets in the flags file, where
  # osqueryd reads them. In options they would be ignored.
  validation {
    condition     = alltrue([for k in keys(var.options) : !can(regex("^(logger_plugin|logger_path|logger_rotate.*|config_plugin|config_path|disable_events|enable_file_events|tls_.*|enroll_.*|distributed_.*|disable_distributed)$", k))])
    error_message = "options can't set the logger, config plugin, events, TLS, enroll or distributed flags. Use the circuit's inputs for those."
  }

  validation {
    condition     = alltrue([for k in keys(var.options) : can(regex("^[a-z0-9_]+$", k))])
    error_message = "Option names use lower-case letters, digits and _, such as schedule_splay_percent."
  }
}

variable "schedule" {
  type = map(object({
    query    = string
    interval = number
    snapshot = optional(bool, false)
  }))
  default     = {}
  description = "Scheduled queries, by name, such as { os_version = { query = \"SELECT * FROM os_version;\", interval = 3600 } }. interval is in seconds. snapshot = true logs the whole result each time to the snapshots log, rather than what changed to the results log."

  validation {
    condition     = alltrue([for name, q in var.schedule : can(regex("^[a-zA-Z0-9_.-]+$", name)) && q.interval >= 1 && floor(q.interval) == q.interval && trimspace(q.query) != ""])
    error_message = "Each scheduled query needs a name of letters, digits, ., - and _, a query, and an interval of 1 or more whole seconds."
  }
}

variable "packs" {
  type        = list(string)
  default     = []
  description = "Query packs osquery ships, by name, such as [\"incident-response\", \"ossec-rootkit\"]. They're read from /opt/osquery/share/osquery/packs."

  validation {
    condition     = alltrue([for p in var.packs : contains(["hardware-monitoring", "incident-response", "it-compliance", "osquery-monitoring", "ossec-rootkit", "vuln-management", "osx-attacks", "unwanted-chrome-extensions", "windows-attacks", "windows-hardening"], p)])
    error_message = "packs must be names of packs osquery ships: hardware-monitoring, incident-response, it-compliance, osquery-monitoring, ossec-rootkit or vuln-management, or one of the macOS and Windows packs, which do nothing on Linux."
  }
}

variable "custom_packs" {
  type = map(object({
    queries = map(object({
      query    = string
      interval = number
      snapshot = optional(bool, false)
    }))
    platform  = optional(string)
    discovery = optional(list(string))
  }))
  default     = {}
  description = "Packs of your own, by name, written into the config. Each has queries, like schedule, and optionally platform, such as \"linux\", and discovery, a list of queries that must all return rows for the pack to run."

  validation {
    condition     = alltrue([for name in keys(var.custom_packs) : can(regex("^[a-zA-Z0-9_.-]+$", name))])
    error_message = "Pack names use letters, digits, ., - and _."
  }

  validation {
    condition     = alltrue(flatten([for p in values(var.custom_packs) : [for q in values(p.queries) : q.interval >= 1 && floor(q.interval) == q.interval && trimspace(q.query) != ""]]))
    error_message = "Each query in a pack needs a query and an interval of 1 or more whole seconds."
  }
}

variable "file_paths" {
  type        = map(list(string))
  default     = {}
  description = "File integrity monitoring: paths to watch, by category, such as { etc = [\"/etc/%%\"], ssh = [\"/root/.ssh/%%\"] }. % matches within a directory, %% recursively. When set, the circuit turns on file events and schedules a file_events query."

  validation {
    condition     = alltrue(flatten([for paths in values(var.file_paths) : [for p in paths : startswith(p, "/")]]))
    error_message = "Each of file_paths must be an absolute path, such as \"/etc/%%\"."
  }
}

variable "file_events_interval" {
  type        = number
  default     = 300
  description = "Seconds between runs of the file_events query that logs file changes, when file_paths is set."

  validation {
    condition     = var.file_events_interval >= 1 && floor(var.file_events_interval) == var.file_events_interval
    error_message = "file_events_interval must be a whole number of seconds, 1 or more."
  }
}

variable "log_rotate_size" {
  type        = number
  default     = 26214400
  description = "Size in bytes at which osquery rotates its results and snapshots logs in /var/log/osquery. The default is 25 MiB."

  validation {
    condition     = var.log_rotate_size >= 1024 && floor(var.log_rotate_size) == var.log_rotate_size
    error_message = "log_rotate_size must be a whole number of bytes, 1024 or more."
  }
}

variable "log_rotate_max_files" {
  type        = number
  default     = 25
  description = "Rotated logs osquery keeps of each kind before deleting the oldest."

  validation {
    condition     = var.log_rotate_max_files >= 1 && floor(var.log_rotate_max_files) == var.log_rotate_max_files
    error_message = "log_rotate_max_files must be a whole number, 1 or more."
  }
}

variable "fleet" {
  type = object({
    address              = string
    server_certs         = optional(string)
    host_identifier      = optional(string, "uuid")
    config_refresh       = optional(number, 10)
    distributed_interval = optional(number, 10)
  })
  default     = null
  description = "A Fleet server to enroll with, such as { address = \"fleet.example.com:8080\", server_certs = \"/etc/osquery/fleet.pem\" }. server_certs is a CA bundle already on the host; when null, osquery's own bundle of public CAs. Fleet then supplies the config, and results go to Fleet as well as the local log. Needs enroll_secret."

  validation {
    condition     = var.fleet == null || can(regex("^[a-zA-Z0-9.-]+(:[0-9]+)?$", try(var.fleet.address, "")))
    error_message = "fleet.address is a host name or address with an optional port, such as \"fleet.example.com:8080\", without https://."
  }

  validation {
    condition     = var.fleet == null || try(startswith(var.fleet.server_certs, "/"), true)
    error_message = "fleet.server_certs must be an absolute path on the host."
  }

  validation {
    condition     = var.fleet == null || contains(["uuid", "hostname", "instance", "ephemeral", "specified"], try(var.fleet.host_identifier, ""))
    error_message = "fleet.host_identifier is one of uuid, hostname, instance, ephemeral or specified."
  }
}

variable "enroll_secret" {
  type        = string
  default     = null
  ephemeral   = true
  sensitive   = true
  description = "Fleet enroll secret, when fleet is set. Pass it at run time with -var or TF_VAR_enroll_secret; it never reaches state or the plan."

  validation {
    condition     = var.enroll_secret != null || var.fleet == null
    error_message = "enroll_secret is required when fleet is set."
  }
}
