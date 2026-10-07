#!/usr/bin/env bash

WORKLOAD_TOKEN=$(kubectl create token -n basseng workload1 --audience nais)
curl -sS  \
   "https://sts.dev.dev-nais.cloud.nais.io/token" \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
  -d "client_assertion=${WORKLOAD_TOKEN}" \
  -d "subject_token=${WORKLOAD_TOKEN}" \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
  -d 'requested_token_type=urn:ietf:params:oauth:token-type:access_token' \
  -d "audience=env1:basseng:workload2" | jq -r '.access_token' | step crypto jwt inspect --insecure | jq -r .
