#!/usr/bin/env bash

WORKLOAD_TOKEN=$(kubectl create token -n tommy workload1 --audience nais --duration=10m)
curl -sS  \
   "https://sts.dev.dev-nais.cloud.nais.io/token" \
  -d 'grant_type=client_credentials' \
  -d 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
  -d "client_assertion=${WORKLOAD_TOKEN}" \
  -d "scope=dev:trong:workload2" | jq -r '.access_token' | step crypto jwt inspect --insecure | jq -r .
