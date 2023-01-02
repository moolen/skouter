FROM alpine
RUN apk add curl
COPY bin/skouter /bin/skouter

ENTRYPOINT ["/bin/skouter"]
