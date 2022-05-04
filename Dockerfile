# TODO: use pypy:2.7-7.3.0-slim
FROM python:3.8-alpine

ENV USER=${USER:-stackguardian}
ENV USER_DIR=${USER_DIR:-/opt/stackguardian}
ENV RUNNER_SOURCE_DIR=${RUNNER_SOURCE_DIR:-/opt/stackguardian/runner}
ARG log_level
ENV LOG_LEVEL=${log_level}
ENV SG_NODE_TOKEN=${SG_NODE_TOKEN:-}
ENV SG_NODE_API_ENDPOINT=${SG_NODE_API_ENDPOINT:-https://api.beta.stackguardian.io/api/v1/}

# make a pipe fail on the first failure
SHELL ["/bin/sh", "-e", "-o", "pipefail", "-c"]

# ensure we only use apk repositories over HTTPS (altough APK contain an embedded signature)
RUN echo "https://alpine.global.ssl.fastly.net/alpine/v$(cut -d . -f 1,2 < /etc/alpine-release)/main" > /etc/apk/repositories \
	&& echo "https://alpine.global.ssl.fastly.net/alpine/v$(cut -d . -f 1,2 < /etc/alpine-release)/community" >> /etc/apk/repositories

# Update base system
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates

RUN pip install pipenv && \
    addgroup -g 911 -S ${USER} && \
    adduser -s /bin/true -u 911 -D -h ${USER_DIR} ${USER} -G ${USER} && \
    mkdir -p ${RUNNER_SOURCE_DIR} && \
    apk update && \
    apk add git curl docker=20.10.14-r1

WORKDIR ${RUNNER_SOURCE_DIR}

COPY --chown=${USER}:root . .

RUN pipenv lock --requirements > requirements.txt && \
    pip install -r requirements.txt

# Remove existing crontabs, if any.
RUN rm -fr /var/spool/cron \
	&& rm -fr /etc/crontabs \
	&& rm -fr /etc/periodic

# Remove all but a handful of admin commands.
RUN find /sbin /usr/sbin \
  ! -type d -a ! -name apk -a ! -name ln \
  -delete

# Remove world-writeable permissions except for /tmp/
RUN find / -xdev -type d -perm +0002 -exec chmod o-w {} + \
	&& find / -xdev -type f -perm +0002 -exec chmod o-w {} + \
	&& chmod 777 /tmp/ \
  && chown ${USER}:root /tmp/

# Remove unnecessary accounts, excluding current app user and root
RUN sed -i -r "/^(${USER}|root|nobody)/!d" /etc/group \
  && sed -i -r "/^(${USER}|root|nobody)/!d" /etc/passwd

# Remove interactive login shell for everybody
RUN sed -i -r 's#^(.*):[^:]*$#\1:/sbin/nologin#' /etc/passwd

# Disable password login for everybody
RUN while IFS=: read -r username _; do passwd -l "$username"; done < /etc/passwd || true

# Remove temp shadow,passwd,group
RUN find /bin /etc /lib /sbin /usr -xdev -type f -regex '.*-$' -exec rm -f {} +

# Ensure system dirs are owned by root and not writable by anybody else.
RUN find /bin /etc /lib /sbin /usr -xdev -type d \
  -exec chown root:root {} \; \
  -exec chmod 0755 {} \;

# Remove suid & sgid files
RUN find /bin /etc /lib /sbin /usr -xdev -type f -a \( -perm +4000 -o -perm +2000 \) -delete

# Remove dangerous commands
RUN find /bin /etc /lib /sbin /usr -xdev \( \
  -iname hexdump -o \
  -iname chgrp -o \
  -iname ln -o \
  -iname od -o \
  -iname strings -o \
  -iname su -o \
  -iname sudo \
  \) -delete

# Remove init scripts since we do not use them.
RUN rm -fr /etc/init.d /lib/rc /etc/conf.d /etc/inittab /etc/runlevels /etc/rc.conf /etc/logrotate.d

# Remove kernel tunables
RUN rm -fr /etc/sysctl* /etc/modprobe.d /etc/modules /etc/mdev.conf /etc/acpi

# Remove root home dir
RUN rm -fr /root

# Remove fstab
RUN rm -f /etc/fstab

# Remove any symlinks that we broke during previous steps
RUN find /bin /etc /lib /sbin /usr -xdev -type l -exec test ! -e {} \; -delete

RUN chmod u+r src/runner/main.py

USER ${USER}

CMD /usr/local/bin/python src/runner/main.py