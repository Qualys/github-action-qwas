#!/busybox/sh

HOME="/home/app"

: ${SERVICE_NAME:="github-was-action"}
: ${SPRING_ACTIVE_PROFILE:="override"}
: ${LOGS_DIR:="/var/log/app/"}

JAVAOPTS="-server \
      -Dlogs-dir=$LOGS_DIR \

      -Dspring.profiles.active=$SPRING_ACTIVE_PROFILE \

      -Dspring.application.name=$SERVICE_NAME \

      -XX:+UseG1GC \
      -XX:MaxGCPauseMillis=200 \
      -XX:+ScavengeBeforeFullGC \
      -Dio.netty.leakDetectionLevel=simple \
      -XX:+DisableExplicitGC \
      -XX:+AlwaysPreTouch \
      -Xss1m"

echo $JAVAOPTS

exec java $JAVAOPTS -jar $HOME/github-was-action.jar