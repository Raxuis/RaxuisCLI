# GoReleaser builds the binary and drops it into the build context; this image
# only packages it. distroless/static ships CA certificates + tzdata, which the
# TLS/DNS commands need. Kept as root so raw-socket / low-level network commands
# work inside the container.
FROM gcr.io/distroless/static-debian12

COPY raxuiscli /usr/bin/raxuiscli

ENTRYPOINT ["/usr/bin/raxuiscli"]
