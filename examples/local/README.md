# Local example

Applies circuit-osquery to a throwaway Rocky Linux 10 container with systemd. You need Conn3x and Podman.

The host container runs privileged, so osqueryd sees the container the way it would a real machine, which is simplest with rootful Podman. On a Mac, use the Podman machine's root connection. On Linux, use `sudo podman`:

```sh
export CONTAINER_CONNECTION=podman-machine-default-root   # macOS
export PODMAN="sudo podman"                               # Linux
./up.sh
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` The example schedules `os_version` every 10 seconds and watches `/etc`, so within half a minute there's something to read:

```sh
ssh -p 2294 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1
touch /etc/hello-osquery
sleep 20
tail -n 3 /var/log/osquery/osqueryd.results.log
osqueryi --json "SELECT version FROM osquery_info"
```

`up.sh` listens on `127.0.0.1:2294`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINERFILE` to test another distro, such as one of the images in Conn3x's `test/images`, which CI uses.

`./down.sh` removes the container, its volumes, the key and the state.
