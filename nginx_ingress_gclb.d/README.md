# GCLB with Nginx Ingress Controller
## Inspired by https://medium.com/google-cloud/secure-your-nginx-ingress-controller-behind-cloud-armor-805d6109af86

### My env
* GKE private cluster
* Autopilot

### Prerequisites
* This does not create a dns zone.  You can add that Terraform in [main.tf](./main.tf) or use an existing one

### Steps
* Run Terraform
  * Fill in where it says FILL_ME_IN
* Navigate to your Private GKE Cluster using Tunneling. I tunnel through the bastion created in the Terraform.
  * Example.  Your mileage may vary.
    ```
    $ gcloud compute ssh <bastion vm name> --tunnel-through-iap --project=<gcp project> --ssh-key-expire-after 1h -- -o ExitOnForwardFailure=yes -M -S /tmp/sslsock-yogibear-8888 -L8888:127.0.0.1:8888 -f sleep 7200
    $ gcloud container clusters get-credentials <GKE cluster name> --region us-central1 --project <gcp project> --internal-ip
    ```
* Install NGINX Ingress Controller like so
    ```
    $ helm upgrade --install nginx-ingress ingress-nginx/ingress-nginx \
      --namespace ingress-nginx \
      --create-namespace \
      --set controller.kind=DaemonSet \
      --set controller.hostNetwork=false \
      --set controller.admissionWebhooks.enabled=false \
      -f ingress_controller_values.yaml
    ```

* Create a namespace **whereami** `kubectl create namespace whereami`
* Follow the instructions in the article to apply the deployment and service.
* Navigate to the Registry to find the appropriate tag, edit the `whereami-ingress.yaml` accordingly.
  * `kubectl apply -f whereami.yaml`

### Navigation
-  Non Wildcard: https://my.domain
- Wildcard: https://whatever.my.domain 
