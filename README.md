# Clouds Modules
This is a module to provide cloud manipulations. It includes AWS, Azure, GCP and OCI.
# How To Use This
* CSP<br>
type: string<br>
```python
CSP = "aws"
CSP = "gcp"
CSP = "azure"
CSP = "oci"
```
* CRED<br>
type: dict<br>
```python
# AWS CRED
CRED = {
    aws_key="",
    aws_secret=""}

# Azure CRED
CRED = {
    subscription_id= "",
    tenant_id="",
    client_id="",
    client_secret=""
}

# GCP CRED
CRED = {
    project_id="",
    file_path=""
}

# OCI CRED
CRED = {
    compartment_id="",
    user_ocid="",
    fingerprint="",
    tenancy_ocid="",
    region=""
    key_file=""
}

# VMW (VMware) CRED
CRED = {
    ip="",
    username="",
    password=""
}
```
## Initialize
### Initialize from cloud credentials using factory method get_cloud_instance
```python
from avxt.lib.clouds import get_cloud_instance
cloud_obj = get_cloud_instance(CSP, CRED)
```
### Initialize from cloud credentials classmethod
```python
from avxt.lib.clouds import AWS
cloud_obj = AWS(CRED)
```
