# rbw for unattended jobs: `rbw backup` and `rbw mirror`, with gpg for
# encrypted backups and cron for schedules. No wrapper scripts: mount an rbw
# config.json whose accounts unlock from files (`unlock.files`, e.g. Docker
# secrets) and run rbw directly. See docs/auto.md.

# hadolint ignore=DL3007
ARG RBW_IMAGE=ghcr.io/pschmitt/rbw:latest
FROM ${RBW_IMAGE} AS rbw

# hadolint ignore=DL3007
FROM ubuntu:latest
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates cron gnupg && \
    rm -rf /var/lib/apt/lists/* /etc/cron.d/* /etc/cron.daily/* \
      /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/*

COPY --from=rbw /usr/bin/rbw /usr/bin/rbw
COPY --from=rbw /usr/bin/rbw-agent /usr/bin/rbw-agent

# rbw's config (config.json), local cache and device id. Keep the state in a
# volume: a new device id each run makes bitwarden.com register a new device
# and send a new-login email every time.
VOLUME ["/root/.config/rbw", "/root/.local/share/rbw", "/data"]

# One-off: `docker run IMAGE backup /data --retention-days 30 ...`.
# Scheduled: `docker run --entrypoint cron IMAGE -f` with a crontab mounted
# at /etc/cron.d/rbw.
ENTRYPOINT ["/usr/bin/rbw"]
CMD ["--help"]
