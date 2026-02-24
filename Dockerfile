FROM alpine:3.19

RUN apk add --no-cache ca-certificates git

COPY nexora /usr/local/bin/nexora

ENTRYPOINT ["/usr/local/bin/nexora"]
CMD ["--help"]
