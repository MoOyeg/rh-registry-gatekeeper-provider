
#TODO write curl queries to test provider
#Depreacated Image
curl -s "https://catalog.redhat.com/api/containers/v1/repositories/registry/registry.access.redhat.com/repository/jboss-webserver-5/webserver54-openjdk8-tomcat9-openshift-rhel7" -H  "accept: application/json" 
 

curl -s "https://catalog.redhat.com/api/containers/v1/repositories/registry/registry.access.redhat.com/repository/jboss-webserver-5/webserver54-openjdk8-tomcat9-openshift-rhel7/tag/latest" -H  "accept: application/json" > repo_with_tag.json

 curl -k -X POST https://localhost:8090/validate -H 'Content-Type: application/json' -d "{\"apiVersion\":\"externaldata.gatekeeper.sh/v1beta1\",\"kind\":\"ProviderRequest\",\"request\":{\"keys\":[\"jboss-webserver-5/webserver54-openjdk8-tomcat9-openshift-rhel7\"]}}"
 curl -k -X POST https://localhost:8090/validate -H 'Content-Type: application/json' -d "{\"apiVersion\":\"externaldata.gatekeeper.sh/v1beta1\",\"kind\":\"ProviderRequest\",\"request\":{\"keys\":[\"error_test/image:latest\"]}}"


 curl -s "https://catalog.redhat.com/api/containers/v1/repositories/registry/registry.access.redhat.com/repository/redhat-openjdk-18/openjdk18-openshift" -H  "accept: application/json" 

 curl -X GET -s "https://catalog.redhat.com/api/containers/v1/images/registry/registry.access.redhat.com/repository/redhat-openjdk-18/openjdk18-openshift/manifest_digest/sha256:c5d58eab73250ba6d9c9f75ffcf38de9567ce057aa21d547cb29e27a6b61ccf1" -H  "accept: application/json"


repositories.tags.name=="1.15-7.1693227984"
 curl -X 'GET' \
  'https://catalog.redhat.com/api/containers/v1/repositories/registry/registry.access.redhat.com/repository/redhat-openjdk-18%2Fopenjdk18-openshift/images?page_size=100&filter=repositories.tags.name%3D%3D%221.15-7.1693227984%22' \
  -H 'accept: application/json'


 curl -X 'GET' "https://catalog.redhat.com/api/containers/v1/repositories/registry/registry.access.redhat.com/repository/ubi9/python-311" -H  "accept: application/json" 


 curl -k -X POST https://localhost:8090/validate -H 'Content-Type: application/json' -d "{\"apiVersion\":\"externaldata.gatekeeper.sh/v1beta1\",\"kind\":\"ProviderRequest\",\"request\":{\"keys\":[\"registry.redhat.io/multicluster-engine/cluster-proxy-addon-rhel8@sha256:148eab1cf1e03cdd8b40cbf8923932898996740187a7142915b1c2250bd7bc7a\"]}}"