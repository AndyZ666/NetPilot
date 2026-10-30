FROM alpine:3.24

RUN apk add --no-cache dnsmasq iproute2 python3

COPY dnsmasq.conf /etc/dnsmasq.conf
COPY R6.cfg /srv/ztp/R6.cfg
COPY start.sh /usr/local/bin/start-ztp
COPY http_server.py /usr/local/bin/ztp-http.py
RUN chmod 755 /usr/local/bin/start-ztp

ENTRYPOINT ["/usr/local/bin/start-ztp"]
