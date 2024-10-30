FROM alpine:latest
LABEL maintainer="Mozilla Release Engineering <release+docker@mozilla.com>"

# Add worker user
RUN mkdir -p /builds && \
    adduser -h /builds/worker -s /bin/ash -D worker && \
    mkdir /builds/worker/artifacts && \
    chown worker:worker /builds/worker/artifacts

# Update repositories
RUN apk update

# Setup Python
# %include requirements.txt
ADD topsrcdir/requirements.txt /requirements.txt
RUN apk add --no-cache python3 py3-pip && \
    python3 -m pip install --no-cache --upgrade --break-system-packages pip setuptools && \
    python3 -m pip install --no-cache --break-system-packages -r /requirements.txt

# Setup nodejs/npm (to get netlify-cli, necessary to deploy netlify functions)
RUN apk add --no-cache npm && \
    npm install -g netlify-cli --force

# Setup other dependencies
RUN apk add bash coreutils curl git gzip jq tar zip

# %include-run-task

ENV SHELL=/bin/ash \
    HOME=/builds/worker \
    PATH=/builds/worker/.local/bin:$PATH

VOLUME /builds/worker/checkouts
VOLUME /builds/worker/.cache

# Set a default command useful for debugging
CMD ["/bin/ash"]
