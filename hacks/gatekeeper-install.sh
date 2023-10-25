#/bin/bash 

#Unmaintained script to help install Gatekeeper via Helm


oc new-project gatekeeper-system
oc project gatekeeper-system
oc create serviceaccount gatekeeper-admin --namespace gatekeeper-system
oc annotate serviceaccount/gatekeeper-admin meta.helm.sh/release-name=helmsgate --namespace gatekeeper-system
oc annotate serviceaccount/gatekeeper-admin meta.helm.sh/release-namespace=gatekeeper-system --namespace gatekeeper-system
oc label serviceaccount/gatekeeper-admin app.kubernetes.io/managed-by=Helm --namespace gatekeeper-system --overwrite=true
oc label serviceaccount/gatekeeper-admin meta.helm.sh/release-name=helmsgate --namespace gatekeeper-system --overwrite=true

oc create serviceaccount gatekeeper-admin-upgrade-crds --namespace gatekeeper-system
oc annotate serviceaccount/gatekeeper-admin-upgrade-crds meta.helm.sh/release-name=helmsgate --namespace gatekeeper-system
oc annotate serviceaccount/gatekeeper-admin-upgrade-crds meta.helm.sh/release-namespace=gatekeeper-system --namespace gatekeeper-system
oc label serviceaccount/gatekeeper-admin-upgrade-crds app.kubernetes.io/managed-by=Helm --namespace gatekeeper-system --overwrite=true
oc label serviceaccount/gatekeeper-admin-upgrade-crds meta.helm.sh/release-name=helmsgate --namespace gatekeeper-system --overwrite=true


oc create serviceaccount gatekeeper-update-namespace-label --namespace gatekeeper-system
oc annotate serviceaccount/gatekeeper-update-namespace-label meta.helm.sh/release-name=helmsgate --namespace gatekeeper-system
oc annotate serviceaccount/gatekeeper-update-namespace-label meta.helm.sh/release-namespace=gatekeeper-system --namespace gatekeeper-system
oc label serviceaccount/gatekeeper-update-namespace-label app.kubernetes.io/managed-by=Helm --namespace gatekeeper-system --overwrite=true
oc label serviceaccount/gatekeeper-update-namespace-label meta.helm.sh/release-name=helmsgate --namespace gatekeeper-system --overwrite=true

oc adm policy add-scc-to-user privileged -z gatekeeper-admin -n gatekeeper-system
oc adm policy add-scc-to-user privileged -z gatekeeper-update-namespace-label -n gatekeeper-system
oc adm policy add-scc-to-user privileged -z gatekeeper-admin-upgrade-crds -n gatekeeper-system

helm install helmsgate gatekeeper/gatekeeper --namespace gatekeeper-system --set controllerManagercontrollerManager.exemptNamespaces=openshift