# hacks for testing in dev-nais

## apply db and sa

```shell
kubectl apply -f hack/
```

## allow port forward to db

```shell
kubectl patch validatingadmissionpolicybinding \
  protect-cloudnative-pg-pods-connection \
  --type=merge \
  -p '{"spec":{"matchResources":{"namespaceSelector":{"matchExpressions":[{"key":"kubernetes.io/metadata.name","operator":"NotIn","values":["nais-system"]}]}}}}'
```

## port forward to db

```shell
kubectl port-forward -n nais-system svc/sts-db-rw 5555:5432
```

## connect to db

```shell
PGPASSWORD="$(kubectl get secret -n nais-system sts-db-app -o jsonpath='{.data.password}' | base64 --decode)" \
  psql "postgresql://sts@localhost:5555/sts?sslmode=disable"
```

## import testdata

Run from the repository root with the port-forward active.
Both imports run in one transaction.

```shell
PGPASSWORD="$(kubectl get secret -n nais-system sts-db-app -o jsonpath='{.data.password}' | base64 --decode)" \
  psql "postgresql://sts@localhost:5555/sts?sslmode=disable" \
  -X --set=ON_ERROR_STOP=1 --single-transaction \
  -c "\copy clients (id, environment, namespace, name, issuer, allowed_scopes) FROM 'hack/clients.csv' WITH (FORMAT CSV, HEADER)" \
  -c "\copy authorization_policies (owner_client_id, consumer_client_id, roles) FROM 'hack/authorization_policies.csv' WITH (FORMAT CSV, HEADER)"
```

## create a client credentials token

```shell
./hack/client-credentials.sh
```

## create a token exchange token

The workload token serves as both the client assertion and the subject token.

```shell
./hack/token-exchange.sh
```

## cleanup

Stop manual port-forwards, then delete the test resources and database:

```shell
kubectl delete -f hack/
```

If you patched `protect-cloudnative-pg-pods-connection`, restore its original configuration separately.
