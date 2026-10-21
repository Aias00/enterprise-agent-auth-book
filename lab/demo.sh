#!/bin/sh
# Run only against the fixed loopback teaching services. Never prints credentials.
set -eu
json_field() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
user_token=$(curl --fail --silent http://127.0.0.1:9101/login -H 'Content-Type: application/json' -d '{"Subject":"alice","Password":"public-alice-pass"}' | json_field access_token)
curl --fail --silent http://127.0.0.1:9102/call -H "Authorization: Bearer $user_token" -H 'Content-Type: application/json' -d '{"tenant":"acme","kind":"orders","id":"o-100","action":"read"}'
business_token=$(curl --fail --silent http://127.0.0.1:9101/delegate -H 'Authorization: Bearer public-local-proxy-do-not-deploy' -H 'Content-Type: application/json' --data "{\"Token\":\"$user_token\"}" | json_field access_token)
approval_id=$(curl --fail --silent http://127.0.0.1:9103/approve -H "Authorization: Bearer $business_token" -H 'X-Approver-Key: public-local-approver-do-not-deploy' -H 'Content-Type: application/json' -d '{"tenant":"acme","kind":"orders","id":"o-100","action":"refund","amount":1200,"note":"customer request"}' | json_field approval)
payload=$(python3 -c 'import json,sys;print(json.dumps(dict(tenant="acme",kind="orders",id="o-100",action="refund",amount=1200,note="customer request",approval=sys.argv[1])))' "$approval_id")
curl --fail --silent http://127.0.0.1:9102/call -H "Authorization: Bearer $user_token" -H 'Content-Type: application/json' --data "$payload"
status=$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:9102/call -H "Authorization: Bearer $user_token" -H 'Content-Type: application/json' --data "$payload")
[ "$status" = 403 ]
printf 'Replay correctly rejected: HTTP %s\n' "$status"
