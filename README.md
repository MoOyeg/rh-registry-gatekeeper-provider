# rh-registry-gatekeeper-provider







## Steps
We will be enabling our Providers with mTLS and using the [Internal OpenShift Service CA](https://docs.openshift.com/container-platform/4.13/security/certificates/service-serving-certificate.html#add-service-serving) to generate the provider certificates.

- Create Provider Services. Our service is annotated with the service-ca annotation for cert generation.This should create a Configmap with the service-ca called openshift-service-ca.crt and tls certs in a secret called rh-registry-gatekeeper-provider-tls.

    ```bash
    oc create -f ./manifest/service/service.yaml
    ```

-  Obtain the Service CA and use it to create the Provider
   
   ```bash
   export SERVICE_CA_BUNDLE=$(oc extract -n gatekeeper-system configmap/openshift-service-ca.crt --to=- | base64 | tr -d '\n')
   ```

   ```bash
   cat manifest/provider-mutate.yaml | envsubst | oc create -f - -n gatekeeper-system
   ```

   ```bash
   cat manifest/provider-validate.yaml | envsubst | oc create -f - -n gatekeeper-system
   ```

   ```bash
   unset SERVICE_CA_BUNDLE
   ```

- Create our provider deployment. Deployments the gatekeeper-webhook-server-cert CA cert from the gatekeeper install example. If CA is different please change secret.

    ```bash
    oc create -f ./manifest/deployment.yaml -n gatekeeper-system
    ```

With our provider installed we can try a few use cases

1 Don't allow Deperecated Images to Run
  
  - Create Our Constraint and Template
    ```bash
    oc create -f ./policy/validate
    ```


