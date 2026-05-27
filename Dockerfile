FROM alpine:latest

WORKDIR /cloudreve
COPY cloudreve ./cloudreve

RUN apk update \
    && apk add --no-cache tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone \
    && chmod +x ./cloudreve \
    && mkdir -p /data/aria2 \
    && chmod -R 766 /data/aria2 \
    && adduser -D -u 1000 cloudreve \
    && chown -R cloudreve:cloudreve /cloudreve /data

USER cloudreve

EXPOSE 5212
VOLUME ["/cloudreve/uploads", "/cloudreve/avatar", "/data"]

ENTRYPOINT ["./cloudreve"]
