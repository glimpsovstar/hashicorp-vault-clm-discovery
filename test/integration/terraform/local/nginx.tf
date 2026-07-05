# --- Self-signed CA + leaf served by nginx (the "discovered CA on the wire") ---

resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name  = "CLM Integration Root CA"
    organization = "CLM Integration"
  }

  is_ca_certificate     = true
  validity_period_hours = 8760 # 1y

  allowed_uses = [
    "cert_signing",
    "crl_signing",
  ]
}

resource "tls_private_key" "leaf" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "leaf" {
  private_key_pem = tls_private_key.leaf.private_key_pem

  subject {
    common_name  = "nginx"
    organization = "CLM Integration"
  }

  dns_names = ["nginx", "localhost"]
}

resource "tls_locally_signed_cert" "leaf" {
  cert_request_pem   = tls_cert_request.leaf.cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 2160 # 90d

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]
}

resource "docker_image" "nginx" {
  name = "nginx:1.27-alpine"
}

resource "docker_container" "nginx" {
  name  = "clm-int-nginx"
  image = docker_image.nginx.image_id

  networks_advanced {
    name    = docker_network.clm.name
    aliases = ["nginx"]
  }

  ports {
    internal = 443
    external = var.nginx_host_port
  }

  # Serve leaf + CA as the chain so CLM discovers both the leaf and the CA issuer.
  upload {
    file    = "/etc/nginx/certs/fullchain.pem"
    content = "${tls_locally_signed_cert.leaf.cert_pem}${tls_self_signed_cert.ca.cert_pem}"
  }

  upload {
    file    = "/etc/nginx/certs/leaf.key"
    content = tls_private_key.leaf.private_key_pem
  }

  upload {
    file    = "/etc/nginx/conf.d/default.conf"
    content = <<-EOT
      server {
        listen 443 ssl;
        server_name nginx localhost;
        ssl_certificate     /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/leaf.key;
        location / { return 200 "clm integration endpoint\n"; }
      }
    EOT
  }
}
