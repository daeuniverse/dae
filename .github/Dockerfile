# Image published by the release workflows. It copies the release build of
# each platform instead of compiling, so the image runs the same binary as
# the release. The Dockerfile at the repository root builds from source.
FROM alpine
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/usr/bin/dae /usr/local/bin/dae
COPY ${TARGETPLATFORM}/usr/share/dae/ /usr/local/share/dae/
COPY --chmod=0600 empty.dae /etc/dae/config.dae

CMD ["dae"]
ENTRYPOINT ["dae", "run", "-c", "/etc/dae/config.dae"]
