FROM art-hq.intranet.qualys.com:5006/secure/distroless/debian12/zing/java-nonroot:24.08.300.0-2-jre17.0.13.0.101

USER root

WORKDIR /home/app
ADD --chown=app:app ./target/github-was-action.jar /home/app/GitHubActionsQWas-0.0.1-SNAPSHOT.jar
ADD --chown=app:app ./run_service.sh /home/app/run_service.sh

RUN /busybox/mkdir -p /home/app/outputs

VOLUME /home/app/outputs

RUN ["/busybox/chmod", "775", "/home/app/run_service.sh"]

RUN ["/busybox/chmod", "-R", "777", "/home/app/outputs"]

RUN chmod ugo+rwx $JAVA_HOME/lib/security/cacerts

#HEALTHCHECK CMD curl --fail localhost:8081/actuator/health || exit 1
USER app
ENTRYPOINT ["/busybox/sh", "/home/app/run_service.sh"]
