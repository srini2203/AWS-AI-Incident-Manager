# Three-Tier Secure & Highly Available AWS Infrastructure

**Project status: Terraform implementation and validation only.** The infrastructure has not been deployed to a live AWS account.

[![Terraform](https://img.shields.io/badge/IaC-Terraform-623CE4?logo=terraform)]()
[![AWS](https://img.shields.io/badge/Cloud-AWS-FF9900?logo=amazon-aws)]()

## Overview

A three-tier AWS architecture with a web tier (Application Load Balancer), application tier (EC2 Auto Scaling Group), and data tier (Amazon RDS Multi-AZ). The infrastructure is defined using Terraform and was developed as part of hands-on preparation for the AWS Solutions Architect Associate (SAA-C03) certification.

## Architecture

![Architecture](architecture/images/Architecture_Diagram.png)

Full write-up: [architecture/architecture-specification.md](architecture/architecture-specification.md)

## Deployment Status

The Terraform configuration has been written and validated with `terraform validate`. It has **not been applied to a live AWS account**. No live deployment, production operation, or end-to-end AWS availability claim is made for this repository snapshot.

The screenshots in [screenshots/](screenshots/) document hands-on AWS console configuration of the same services during SAA study. See [docs/console-walkthrough.md](docs/console-walkthrough.md) for how those exercises map to the Terraform files. The screenshots should be understood as learning evidence, not proof that this Terraform project was deployed.

## AWS Services Represented

| Service | Intended role |
|---|---|
| VPC and public/private subnets | Network isolation across the three tiers |
| Internet Gateway and NAT Gateway | Public ingress and controlled private egress |
| Application Load Balancer | Layer 7 routing and health checks |
| EC2 Auto Scaling Group | Application capacity and instance replacement |
| Amazon RDS for MySQL (Multi-AZ) | Managed relational database with multi-AZ failover capability |
| AWS Secrets Manager | Storage for database credentials |
| IAM roles | Instance permissions without long-lived credentials |
| Amazon CloudWatch and Amazon SNS | Monitoring and alert notifications |

## Repository Structure

```text
AWS-AI-Incident-Manager/
├── architecture/     — design specification and diagrams
├── terraform/        — Terraform infrastructure configuration
├── docs/             — decisions, security, cost, trade-offs, and console walkthrough
└── screenshots/      — AWS console learning evidence
```

## Getting Started

Requirements: Terraform CLI and an AWS account configured locally if you want to inspect a plan. Running the commands below does not deploy infrastructure.

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Set values appropriate for your own environment.
terraform init
terraform validate
terraform plan
```

Review the plan carefully before considering any apply operation. Applying the configuration may create billable AWS resources.

## Learning Outcomes

- Designing a three-tier VPC network with public and private subnets
- Applying security-group boundaries between tiers
- Modelling an Application Load Balancer and EC2 Auto Scaling Group
- Configuring an RDS Multi-AZ database architecture
- Using IAM roles and Secrets Manager in infrastructure design
- Translating AWS console learning into Infrastructure as Code

## Possible Future Work

These are not implemented or validated in this repository snapshot:

- Deploy and verify the architecture in an AWS account
- Add AWS WAF protection to the load balancer
- Add a CI/CD workflow with GitHub Actions
- Refine least-privilege IAM permissions for Secrets Manager access

## Author

**V. Srinivasan** — Cloud Engineering · AWS · Terraform
