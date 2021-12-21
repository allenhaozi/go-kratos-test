FROM docker.4pd.io/alpine:3.15.0

WORKDIR /

# This is required by daemon connnecting with cri
RUN apk add --no-cache ca-certificates bash tzdata \
	&& cp /usr/share/zoneinfo/Hongkong /etc/localtime

COPY iam-web /usr/local/bin/iam-web

COPY templates /templates

EXPOSE 8080

CMD [ "iam-web" ]
