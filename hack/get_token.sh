WORKLOAD_TOKEN=$(k create token -n basseng workload1 --audience nais)
curl -sSS  \
   "https://sts.dev.dev-nais.cloud.nais.io/token" \
  -d 'grant_type=client_credentials' \
  -d 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
  -d "client_assertion=${WORKLOAD_TOKEN}" \
  -d "scope=env1:basseng:workload2" | jq -r '.access_token' | jwt