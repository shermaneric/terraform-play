# For more info, https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/iap_client

# It's possible we don't need the service account info, but it's here if you need it.
# Create service account for IAP
resource "google_service_account" "iap" {
  account_id   = "iap-service-account"
  display_name = "IAP Service Account"
  project      = google_project.project.project_id
}

# Grant IAP-Secured Web App User role to service account
resource "google_project_iam_member" "iap_web_user" {
  project = google_project.project.project_id
  role    = "roles/iap.httpsResourceAccessor"
  member  = "serviceAccount:${google_service_account.iap.email}"
}

# Enable Workload Identity for the IAP service account
resource "google_service_account_iam_member" "iap_workload_identity" {
  service_account_id = google_service_account.iap.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${google_project.project.project_id}.svc.id.goog[hello-world/iap-service-account]"
}

# If you are running this, your account needs to have owner access to this google group support "email"
# See https://github.com/hashicorp/terraform-provider-google/issues/20204
resource "google_iap_brand" "brand" {
  support_email     = "FILL_ME_IN"
  application_title = "FILL_ME_IN"
  project           = google_project.project.project_id
  depends_on        = [google_project.project]
}

# Use group or owner however you see fit
resource "google_iap_web_iam_member" "tau_eng_access_iap_policy" {
  project = google_project.project.project_id
  role      = "roles/iap.httpsResourceAccessor"
  member    = "group:FILL_ME_IN"
}

resource "google_iap_client" "client" {
  display_name = "FILL_ME_IN"
  brand        =  google_iap_brand.brand.name
}


resource "google_secret_manager_secret" "iap_secret" {
  project = google_project.project.project_id
  secret_id = "iap-client-secret"
  replication {
    user_managed {
      replicas {
        location = "us-central1"
      }
      replicas {
        location = "us-east1"
      }
    }
  }
}

resource "google_secret_manager_secret_version" "iap_secret_version" {
  secret = google_secret_manager_secret.iap_secret.name
  secret_data_wo  = jsonencode({
    "client_secret": google_iap_client.client.secret
    "client_id": google_iap_client.client.client_id
  })
}

