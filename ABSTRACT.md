# Table of Contents

- [Table of Contents](#table-of-contents)
  - [Project Overview](#project-overview)
    - [Objective](#objective)
    - [Key Goals](#key-goals)
  - [Architectural Design](#architectural-design)
    - [High-Level Architecture](#high-level-architecture)
    - [Workflow Overview](#workflow-overview)
  - [Components and Tools](#components-and-tools)
    - [Primary Components](#primary-components)
  - [Secret Storage and Management](#secret-storage-and-management)
    - [Choosing the Right Storage](#choosing-the-right-storage)
    - [Encrypting Secrets](#encrypting-secrets)
    - [Managing Keys with KeyManager](#managing-keys-with-keymanager)
  - [Automating GitLab Variable Management](#automating-gitlab-variable-management)
    - [Understanding GitLab Variables](#understanding-gitlab-variables)
    - [Automating with GitLab API](#automating-with-gitlab-api)
    - [Sample Workflow for Updating GitLab Variables](#sample-workflow-for-updating-gitlab-variables)
  - [Integration with Kubernetes and Helm](#integration-with-kubernetes-and-helm)
    - [Using Helm for Deployment](#using-helm-for-deployment)
    - [Injecting Secrets into Kubernetes](#injecting-secrets-into-kubernetes)
    - [Managing Different Environments](#managing-different-environments)
    - [Automating Helm Deployments](#automating-helm-deployments)

## Project Overview

### Objective
Develop a secure, dynamic, and automated system to manage secrets and environment variables for projects deployed in Kubernetes using Helm and GitLab CI/CD, without relying on external secret management services like HashiCorp Vault or Dotenv Cloud.

### Key Goals
- **Dynamic Management**: Easily add, update, and remove secrets without manual intervention.
- **Security**: Ensure secrets are stored, transmitted, and accessed securely.
- **Automation**: Automate the synchronization of secrets between storage, GitLab, and Kubernetes.
- **Version Control**: Maintain version history and backups of secrets.
- **Environment Support**: Handle multiple environments (dev, prod, pre-prod, etc.) seamlessly.

## Architectural Design

### High-Level Architecture
- **Secret Storage**: Utilize Google Cloud Platform (GCP) to store encrypted secrets securely.
- **Key Management**: Manage encryption keys using the custom KeyManager class.
- **Encryption/Decryption**: Use the EnvCryptor Docker image to encrypt/decrypt secrets.
- **GitLab Integration**: Automate the updating of GitLab CI/CD variables via GitLab API.
- **Kubernetes Integration**: Deploy secrets to Kubernetes using Helm charts.
- **Backup and Versioning**: Implement backup strategies and version control for secrets.
- **Automation Pipeline**: Create scripts or CI/CD pipelines to orchestrate the above components.

### Workflow Overview
1. **Secret Creation/Update**: Developers add or update secrets locally or via a centralized interface.
2. **Encryption**: Secrets are encrypted using EnvCryptor with keys managed by KeyManager.
3. **Storage**: Encrypted secrets are stored in a secure GCP bucket.
4. **Synchronization**: Automated scripts retrieve encrypted secrets, decrypt them as needed, and update GitLab variables.
5. **Deployment**: Helm charts use GitLab variables to inject secrets into Kubernetes deployments.
6. **Backup & Versioning**: Regular backups and versioning of secrets are maintained in GCP.
7. **Monitoring**: Continuous monitoring ensures the integrity and security of secrets.

## Components and Tools

### Primary Components
- **EnvCryptor**: Encrypts and decrypts secrets.
- **KeyManager**: Manages encryption keys (creation, rotation, deletion).
- **GCP Storage**: Securely stores encrypted secrets.
- **GitLab API**: Automates the management of GitLab CI/CD variables.
- **Helm Charts**: Deploy applications to Kubernetes, injecting secrets from GitLab variables.
- **Backup and Version Control**: Maintain backups and version history of secrets.
- **Docker Registry**: Store and distribute the EnvCryptor Docker image.
- **Automation Scripts**: Orchestrate the encryption, storage, synchronization, and deployment processes.

## Secret Storage and Management

### Choosing the Right Storage
- **Google Cloud Storage (GCS) Bucket**:
  - **Advantages**: Scalable, durable, supports encryption at rest and in transit, access control via IAM, versioning capabilities.
  - **Considerations**: Ensure bucket policies are strict to prevent unauthorized access, enable Object Versioning for backup and recovery.

### Encrypting Secrets
- **Process**:
  - **Encryption Key Management**: Use the KeyManager to generate and manage encryption keys.
  - **Encrypt Secrets**: Utilize EnvCryptor to encrypt secrets before storing them in GCS.
  - **Store Encrypted Secrets**: Save the encrypted secrets in the designated GCS bucket.
- **Security Measures**:
  - **Key Length**: Use strong keys (e.g., 256-bit for AES-256).
  - **Key Rotation**: Regularly rotate keys to minimize risk.
  - **Access Controls**: Limit access to keys and secrets to only necessary services/users.

### Managing Keys with KeyManager
- **Functionalities**:
  - **Generate Key**: Create a new encryption key.
  - **Load Key**: Retrieve an existing key for encryption/decryption.
  - **Rotate Key**: Replace an old key with a new one, re-encrypting secrets as necessary.
  - **List Keys**: View all available keys.
  - **Delete Key**: Remove a key that is no longer needed.
- **Implementation Considerations**:
  - **Secure Storage**: Store keys in a dedicated, secure directory with strict permissions.
  - **Backup**: Regularly back up keys to prevent loss.
  - **Audit Trails**: Log all key management activities for auditing purposes.

## Automating GitLab Variable Management

### Understanding GitLab Variables
- **CI/CD Variables**: Store environment-specific variables that can be used in GitLab CI/CD pipelines.
- **Types**:
  - **Protected Variables**: Only available to protected branches or tags.
  - **Masked Variables**: Values are hidden in job logs.

### Automating with GitLab API
- **Authentication**:
  - **Personal Access Token (PAT)**: Generate a PAT with appropriate scopes (e.g., api) to interact with GitLab API.
  - **Security**: Store PAT securely, possibly using GitLab's own CI/CD variables or GCP Secret Manager.
- **API Endpoints**:
  - **Set Variable**: `POST /projects/:id/variables`
  - **Update Variable**: `PUT /projects/:id/variables/:key`
  - **Delete Variable**: `DELETE /projects/:id/variables/:key`
  - **List Variables**: `GET /projects/:id/variables`
- **Automation Steps**:
  - **Retrieve Encrypted Secrets**: Fetch from GCS bucket.
  - **Decrypt Secrets**: Use EnvCryptor to decrypt.
  - **Update GitLab Variables**: Use GitLab API to create/update variables per project and environment.
- **Handling Multiple Projects and Environments**:
  - **Mapping**: Maintain a mapping of secrets to specific GitLab projects and environments.
  - **Scripts**: Develop scripts that iterate through projects/environments to update variables accordingly.
- **Error Handling**:
  - **Retries**: Implement retry logic for API failures.
  - **Logging**: Log successes and failures for monitoring.

### Sample Workflow for Updating GitLab Variables
1. **Fetch Encrypted Secrets**: Use gcloud CLI or GCS APIs to retrieve encrypted secrets.
2. **Decrypt Secrets**: Invoke the EnvCryptor Docker image to decrypt secrets.
3. **Interact with GitLab API**: Use scripts (Python with requests library, Bash with curl, etc.) to authenticate and update variables.
4. **Verification**: Optionally, verify that variables are updated correctly by fetching them via API.

## Integration with Kubernetes and Helm

### Using Helm for Deployment
- **Helm Charts**: Define Kubernetes manifests using Helm templates, allowing for dynamic injection of secrets.

### Injecting Secrets into Kubernetes
- **Kubernetes Secrets**:
  - **Creation**: Use Helm to create Kubernetes Secret resources from GitLab variables.
  - **Usage**: Mount secrets as environment variables or files in pods.
- **Helm Templates**:
  - **Dynamic Values**: Use Helm's templating to reference GitLab variables.
  - **Example**:
    ```yaml
    apiVersion: v1
    kind: Secret
    metadata:
      name: {{ .Release.Name }}-secret
    type: Opaque
    data:
      DB_PASSWORD: {{ .Values.dbPassword | b64enc }}
    ```

### Managing Different Environments
- **Values Files**: Maintain separate `values.yaml` files for each environment (dev, prod, pre-prod).
- **Helm Releases**: Deploy separate Helm releases for each environment using respective values files.

### Automating Helm Deployments
- **GitLab CI/CD Integration**: Define GitLab CI/CD jobs to trigger Helm deployments after updating GitLab variables.
- **Example .gitlab-ci.yml snippet**:
  ```yaml
  stages:
    - deploy

  deploy:
    stage: deploy
    script:
      - helm upgrade --install my-release ./my-chart -f values.yaml
