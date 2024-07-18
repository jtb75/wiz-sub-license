# Wiz License Usage per Project

## Description

The `wiz_license_usage_per_project.py` script queries the WizAPI for License Usage data,
saving the results to a an output file.

### Usage via Cron

* Download the script from the terraform directory.
* Customize the script to meet your requirements, if necessary.
* Execute the script in the context of a cron job.
* Profit!

(Use `./wiz_license_usage_per_project.py --help` for a complete list of command-line parameters.)

#### Example

```
wiz_license_usage_per_project.py --all
```

### Usage of Cloud Storage

#### AWS

* Use the environment variable "WIZ_OUTPUT_BUCKET_TYPE" or parameter option of "--bucket_type" set to "S3".
* Use the environment variable "WIZ_OUTPUT_BUCKET_NAME" or parameter option "--bucket_name" set to the bucket name.

#### Azure

* Use the environment variable "WIZ_OUTPUT_BUCKET_TYPE" or parameter option of "--bucket_type" set to "BLOB".
* Use the environment variable "WIZ_OUTPUT_BUCKET_NAME" or parameter option "--bucket_name" set to the **container** name within the Azure Blob storage.
* Use the environment variable "AZURE_STORAGE_CONNECTION_STRING" set to the Access Key Connection String for the targeted Blob.

### Usage via AWS Lamdba

* Download the `wiz-license-usage-per-project` directory.
* Customize the script to meet your requirements, if necessary.
* Create a `terraform/terraform.tfvars` file and populate it with the variables defined in `terraform/main.tf` as "REQUIRED VARIABLES/PARAMETERS".
* Deploy via Terraform.
* Test in AWS.
* Profit!

(Note that all command-line parameters are passed as environment variables, with `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET` encrypted via KMS.)

#### Example

```
cd terraform
vi terraform.tfvars

terraform init
terraform validate
terraform plan
terraform apply
```
