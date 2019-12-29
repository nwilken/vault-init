FROM asuuto/curl-jq:latest
LABEL maintainer="Nate Wilken <wilken@asu.edu>"

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 555 /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]