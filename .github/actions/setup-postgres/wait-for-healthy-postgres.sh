#!/bin/bash
RETRIES=10

until [ $RETRIES -eq 0 ]; do
  # Check if docker compose is available and being used
  if docker compose version >/dev/null 2>&1 && docker compose ps postgres --status running --format json >/dev/null 2>&1; then
    DOCKER_OUTPUT=$(docker compose ps postgres --status running --format json)
    JSON_TYPE=$(echo "$DOCKER_OUTPUT" | jq -r 'type')

    if [ "$JSON_TYPE" == "array" ]; then
      HEALTH_STATUS=$(echo "$DOCKER_OUTPUT" | jq -r '.[0].Health')
    elif [ "$JSON_TYPE" == "object" ]; then
      HEALTH_STATUS=$(echo "$DOCKER_OUTPUT" | jq -r '.Health')
    else
      HEALTH_STATUS="Unknown JSON type: $JSON_TYPE"
    fi
  elif command -v docker-compose >/dev/null 2>&1 && docker-compose ps postgres >/dev/null 2>&1; then
    # Use docker-compose
    DOCKER_OUTPUT=$(docker-compose ps postgres --status running --format json)
    JSON_TYPE=$(echo "$DOCKER_OUTPUT" | jq -r 'type')

    if [ "$JSON_TYPE" == "array" ]; then
      HEALTH_STATUS=$(echo "$DOCKER_OUTPUT" | jq -r '.[0].Health')
    elif [ "$JSON_TYPE" == "object" ]; then
      HEALTH_STATUS=$(echo "$DOCKER_OUTPUT" | jq -r '.Health')
    else
      HEALTH_STATUS="Unknown JSON type: $JSON_TYPE"
    fi
  else
    # Check docker container directly
    if docker ps --filter "name=cl_pg" --filter "status=running" --format "table {{.Names}}" | grep -q cl_pg; then
      HEALTH_STATUS=$(docker inspect cl_pg --format='{{.State.Health.Status}}')
    else
      HEALTH_STATUS="not_running"
    fi
  fi

  echo "postgres health status: $HEALTH_STATUS"
  if [ "$HEALTH_STATUS" == "healthy" ]; then
    exit 0
  fi

  echo "Waiting for postgres server, $((RETRIES--)) remaining attempts..."
  sleep 2
done

exit 1
