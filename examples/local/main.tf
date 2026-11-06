variable "port" {
  type    = number
  default = 2294
}

# CI sets osquery_version to install an older release first, then upgrades
# to the circuit's own pin by applying again without it.
variable "osquery_version" {
  type    = string
  default = null
}

# CI sets these to check the enroll secret reaches the host and not state.
variable "fleet" {
  type    = object({ address = string })
  default = null
}

variable "enroll_secret" {
  type      = string
  default   = null
  ephemeral = true
  sensitive = true
}

module "osquery" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"
  osquery_version      = var.osquery_version
  fleet                = var.fleet
  enroll_secret        = var.enroll_secret

  options = {
    schedule_splay_percent = "10"
  }

  # Short intervals, so results show up within a minute of the apply.
  schedule = {
    os_version = { query = "SELECT name, version FROM os_version;", interval = 10 }
    users      = { query = "SELECT username, uid, shell FROM users;", interval = 60, snapshot = true }
  }

  packs = ["ossec-rootkit"]

  custom_packs = {
    listening = {
      platform = "linux"
      queries = {
        ports = { query = "SELECT pid, port, protocol, address FROM listening_ports;", interval = 60 }
      }
    }
  }

  file_paths = {
    etc = ["/etc/%%"]
  }
  file_events_interval = 10

  log_rotate_size      = 10485760
  log_rotate_max_files = 5
}
