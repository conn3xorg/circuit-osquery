output "config_file" {
  description = "Path of the osquery config the circuit writes on each host."
  value       = local.config_file
}

output "flags_file" {
  description = "Path of the osquery flags file the circuit writes on each host."
  value       = local.flags_file
}

output "results_log" {
  description = "Path of the log scheduled query results go to on each host."
  value       = "${local.log_dir}/osqueryd.results.log"
}
