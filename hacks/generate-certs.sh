#!/bin/bash

#Script to generate the certs for the Provider.
cd ./temp
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -subj "/O=My Org/CN=GKP Data Provider CA" -out ca.crt
openssl genrsa -out server.key 2048
openssl req -newkey rsa:2048 -nodes -keyout server.key -subj "/CN=rhreg-gkp-pro.openshift-gatekeeper-system.svc.cluster.local" -out server.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:rhreg-gkp-pro.openshift-gatekeeper-system.svc.cluster.local") -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
oc create secret tls test-cert --cert=./tls.crt --key=./tls.key -n openshift-gatekeeper-system
oc create configmap ca-test --from-file=./ca.crt -n openshift-gatekeeper-system