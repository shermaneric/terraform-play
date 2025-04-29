terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 4.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.0.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.0.0"
    }
  }
  required_version = ">= 1.0"
}
provider "google" {
  project = local.project
  region  = local.region
}
data "google_client_config" "default" {}

locals {
  project      = "FILL_ME_IN"
  dns_project  = "FILL_ME_IN"
  dns_zone     = "FILL_ME_IN"
  bastion_machine_type = "g1-small"
  region       = "us-central1"
  zone         = "${local.region}-a"
  vpc_name     = "my-network"
  cluster_name = "my-gke-cluster"
  billing_account_id = "FILL_ME_IN"
  gke_master_cidr = "172.16.0.0/28"
  labels = {}
}
# Enable required services
resource "google_project_service" "services" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "sqladmin.googleapis.com",
    "servicenetworking.googleapis.com",
    "cloudkms.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com"
  ])
  
  project = google_project.project.project_id
  service = each.key

  disable_dependent_services = false
  disable_on_destroy        = false
}
# Create the project
resource "google_project" "project" {
  name            = local.project
  project_id      = local.project
  billing_account = local.billing_account_id
  folder_id       = "640286760235"
}
# Wait for project creation
resource "time_sleep" "wait_for_project" {
  depends_on = [google_project.project]
  create_duration = "30s"
}
# Enable services after project creation
resource "google_project_service" "services_after_project" {
  for_each = toset([
    "certificatemanager.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iap.googleapis.com",
    "artifactregistry.googleapis.com",  
    "secretmanager.googleapis.com",
    "sqladmin.googleapis.com",
    "servicenetworking.googleapis.com",
    "cloudkms.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com"
  ])
  
  project = google_project.project.project_id
  service = each.key

  disable_dependent_services = false
  disable_on_destroy        = false

  depends_on = [time_sleep.wait_for_project]
}

module "bastion" {
  depends_on = [google_project_service.services_after_project]
  source                     = "github.com/terraform-google-modules/terraform-google-bastion-host"
  host_project               = google_project.project.project_id
  image_family               = "ubuntu-2204-lts"
  image_project              = "ubuntu-os-cloud"
  labels                     = local.labels
  machine_type               = local.bastion_machine_type
  name                       = "my-gke-cluster-bastion"
  network                    = google_compute_network.vpc.self_link
  project                    = google_project.project.project_id
  service_account_name       = "bastion-sa"
  service_account_roles_supplemental = []
  shielded_vm                = true
  startup_script = <<-EOT
      #!/bin/bash
      set -ex
      sudo apt-get update
      sudo apt-get upgrade -y 
      sudo apt-get install -y tinyproxy
  EOT
  subnet         = google_compute_subnetwork.customer.self_link
  zone           = local.zone
}

# Create VPC
resource "google_compute_network" "vpc" {
  name                    = local.vpc_name
  project                 = google_project.project.project_id
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
}

# Create subnet and External Egress
resource "google_compute_subnetwork" "customer" {
  name          = "customer"
  project       = google_project.project.project_id
  ip_cidr_range = "10.10.0.0/20"
  region        = local.region
  network       = google_compute_network.vpc.id
  description   = "Customer subnet managed by Terraform"
  
  private_ip_google_access = true
  
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata            = "INCLUDE_ALL_METADATA"
  }

  secondary_ip_range {
    range_name    = "ip-range-pods"
    ip_cidr_range = "10.10.16.0/20"
  }

  secondary_ip_range {
    range_name    = "ip-range-services" 
    ip_cidr_range = "10.10.32.0/20"
  }
}

resource "google_compute_router" "router" {
  name    = "${local.cluster_name}-router"
  network = google_compute_network.vpc.name
  region  = local.region

  bgp {
    asn = 64514
  }
}

resource "google_compute_router_nat" "nat" {
  name                               = "${local.cluster_name}-nat"
  router                            = google_compute_router.router.name
  region                            = local.region
  nat_ip_allocate_option            = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Create GKE cluster
module "gke" {
  source = "github.com/terraform-google-modules/terraform-google-kubernetes-engine//modules/beta-autopilot-private-cluster?ref=v36.3.0"

  cluster_resource_labels         = local.labels
  create_service_account          = true
  dns_allow_external_traffic      = true
  deletion_protection             = false
  enable_private_endpoint         = false
  enable_private_nodes            = true
  enable_secret_manager_addon     = true
  filestore_csi_driver            = true # enable filestore csi driver
  grant_registry_access           = true
  ip_range_pods                   = google_compute_subnetwork.customer.secondary_ip_range[0].range_name
  ip_range_services               = google_compute_subnetwork.customer.secondary_ip_range[1].range_name
  horizontal_pod_autoscaling      = true
  enable_vertical_pod_autoscaling = true
  master_ipv4_cidr_block          = "10.0.0.0/28"
  name                            = local.cluster_name
  network                         = google_compute_network.vpc.name
  project_id                      = google_project.project.project_id
  region                          = local.region
  service_account_name            = "gke-root-customer"
  subnetwork                      = "customer"
  zones                           = [local.zone]

  master_authorized_networks = [{
    cidr_block   = "${module.bastion.ip_address}/32",
    display_name = "Customer GKE Bastion Host",
  }]
}

# Backend service/config
resource "google_compute_firewall" "allow_tcp_loadbalancer" {
  name    = "${local.cluster_name}-allow-tcp-loadbalancer"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = [443] # Using 443 as the NGINX_NEG_PORT based on ingress_controller_values.yaml
  }

  source_ranges = [
    "130.211.0.0/22",
    "35.191.0.0/16"
  ]
}

resource "google_compute_health_check" "ingress_nginx" {
  name = "${local.cluster_name}-ingress-nginx-health-check"

  https_health_check {
    port               = 443 # Using 443 as the NGINX_NEG_PORT based on ingress_controller_values.yaml
    request_path       = "/healthz"
  }

  check_interval_sec  = 60
  timeout_sec         = 5
  healthy_threshold   = 1
  unhealthy_threshold = 3
}

resource "google_compute_backend_service" "ingress_nginx_backend" {
  name                  = "${local.cluster_name}-ingress-nginx-backend-service"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol             = "HTTPS"
  port_name            = "https"
  health_checks        = [google_compute_health_check.ingress_nginx.id]

  backend {
    group                 = "projects/${google_project.project.project_id}/zones/${local.zone}/networkEndpointGroups/my-gke-cluster-ingress-nginx-neg"
    balancing_mode        = "RATE"
    capacity_scaler       = 1.0
    max_rate_per_endpoint = 100
  }
  security_policy = google_compute_security_policy.default.id
}

# Frontend service/config

resource "google_compute_url_map" "ingress_nginx_url_map" {
  name            = "${local.cluster_name}-ingress-nginx-loadbalancer"
  default_service = google_compute_backend_service.ingress_nginx_backend.id
  project         = google_project.project.project_id
}

resource "google_compute_target_http_proxy" "ingress_nginx_http_proxy" {
  name             = "${local.cluster_name}-ingress-nginx-http-proxy"
  url_map          = google_compute_url_map.ingress_nginx_url_map.id
}

resource "google_compute_global_address" "ingress_nginx_static_ip" {
  name    = "${local.cluster_name}-public-static-ip"
  project = google_project.project.project_id
}

resource "google_dns_record_set" "my_wildcard_dns" {
  name    = "*.my.domain."
  project = local.dns_project
  type    = "A"
  ttl     = 300
  managed_zone = local.dns_zone
  rrdatas = [google_compute_global_address.ingress_nginx_static_ip.address]
}


# Certificate Manager
resource "google_certificate_manager_dns_authorization" "dns_auth" {
  depends_on = [google_project_service.services_after_project]
  name        = "${local.cluster_name}-dns-auth"
  domain      = "my.domain"
  project     = google_project.project.project_id
}

resource "google_dns_record_set" "certificate_verification" {
  name         = google_certificate_manager_dns_authorization.dns_auth.dns_resource_record[0].name
  type         = google_certificate_manager_dns_authorization.dns_auth.dns_resource_record[0].type
  ttl          = 300
  managed_zone = local.dns_zone
  project      = local.dns_project
  rrdatas      = [google_certificate_manager_dns_authorization.dns_auth.dns_resource_record[0].data]
}

resource "random_id" "tf_prefix" {
  byte_length = 2
}

resource "google_certificate_manager_certificate" "root_cert" {
  name        = "${local.cluster_name}-rootcert-${random_id.tf_prefix.hex}"
  description = "The wildcard cert for ${local.cluster_name}"
  managed {
    domains = ["my.domain", "*.my.domain"]
    dns_authorizations = [
      google_certificate_manager_dns_authorization.dns_auth.id
    ]
  }
  labels = {
    "terraform" : true
  }
}
resource "google_certificate_manager_certificate_map" "root_cert_map" {
  name        = "${local.cluster_name}-cert-map-${random_id.tf_prefix.hex}"
  description = "Certificate map for ${local.cluster_name}"
  labels = {
    "terraform" : true
  }
}

resource "google_certificate_manager_certificate_map_entry" "root_cert_map_entry" {
  name        = "${local.cluster_name}-cert-map-entry-${random_id.tf_prefix.hex}"
  description = "Certificate map entry for ${local.cluster_name}"
  map         = google_certificate_manager_certificate_map.root_cert_map.name
  certificates = [google_certificate_manager_certificate.root_cert.id]
  hostname    = "*.my.domain"
  labels = {
    "terraform" : true
  }
}

resource "google_compute_target_https_proxy" "ingress_nginx_https_proxy" {
  name             = "${local.cluster_name}-ingress-nginx-https-proxy"
  url_map          = google_compute_url_map.ingress_nginx_url_map.id
  certificate_map  = "//certificatemanager.googleapis.com/projects/${google_project.project.project_id}/locations/global/certificateMaps/${local.cluster_name}-cert-map-${random_id.tf_prefix.hex}"
}

resource "google_compute_global_forwarding_rule" "https_forwarding_rule" {
  name                  = "${local.cluster_name}-https-forwarding-rule"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  network_tier          = "PREMIUM"
  port_range           = "443"
  target               = google_compute_target_https_proxy.ingress_nginx_https_proxy.id
  ip_address           = google_compute_global_address.ingress_nginx_static_ip.address
}

### http to https redirect
resource "google_compute_url_map" "http_to_https_redirect" {
  name = "${local.cluster_name}-http-to-https-redirect"
  default_url_redirect {
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    https_redirect = true
    strip_query = false
  }
}

resource "google_compute_target_http_proxy" "http_to_https_redirect" {
  name    = "${local.cluster_name}-http-to-https-redirect-proxy"
  url_map = google_compute_url_map.http_to_https_redirect.id
}

resource "google_compute_global_forwarding_rule" "http_to_https_redirect" {
  name                  = "${local.cluster_name}-http-to-https-redirect-rule"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  network_tier          = "PREMIUM"
  port_range           = "80"
  target               = google_compute_target_http_proxy.http_to_https_redirect.id
  ip_address           = google_compute_global_address.ingress_nginx_static_ip.address
}

# Default Cloud Armor Policy
resource "google_compute_security_policy" "default" {
  name        = "${local.cluster_name}-security-policy"
  description = "Default Cloud Armor security policy with Layer 7 DDoS defense enabled"

  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
    }
  }

  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default rule, higher priority overrides it"
  }
}

