# Run on the host. The example runs os_version every 10 seconds and
# file_events every 10 seconds over /etc, so both land in the results log
# within ~30s.
set -eu
systemctl is-active osqueryd
osqueryi --json "SELECT version FROM osquery_info" | grep -q '"version"'
f=/etc/conn3x-fim-check-$(date +%s)
touch "$f"
for _ in $(seq 40); do
  if grep -q '"name":"os_version"' /var/log/osquery/osqueryd.results.log 2>/dev/null \
    && grep -q "$f" /var/log/osquery/osqueryd.results.log; then
    exit 0
  fi
  sleep 1
done
ls -la /var/log/osquery
journalctl -u osqueryd --no-pager | tail -n 30
exit 1
