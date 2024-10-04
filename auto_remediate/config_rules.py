import json
import sys
import boto3
from botocore.exceptions import ClientError

class ConfigRules:
    def __init__(self, logging):
        self.logging = logging
        self._client_rds = None
        self._client_s3 = None
        self._client_sts = None

    @property
    def client_rds(self):
        if not self._client_rds:
            self._client_rds = boto3.client("rds")
        return self._client_rds

    @property
    def client_s3(self):
        if not self._client_s3:
            self._client_s3 = boto3.client("s3")
        return self._client_s3

    @property
    def client_sts(self):
        if not self._client_sts:
            self._client_sts = boto3.client("sts")
        return self._client_sts

    @property
    def account_number(self):
        return self.client_sts.get_caller_identity()["Account"]

    @property
    def account_arn(self):
        return self.client_sts.get_caller_identity()["Arn"]

    @property
    def region(self):
        return self.client_sts.meta.region_name if self.client_sts.meta.region_name != "aws-global" else "us-east-1"

    def rds_instance_public_access_check(self, resource_id):
        """Sets Publicly Accessible option to False for public RDS Instances"""
        try:
            paginator = self.client_rds.get_paginator("describe_db_instances")
            response = paginator.paginate(DBInstanceIdentifier=resource_id)
            for instance in response["DBInstances"]:
                self.client_rds.modify_db_instance(
                    DBInstanceIdentifier=instance["DBInstanceIdentifier"],
                    PubliclyAccessible=False
                )
                self.logging.info(f"Disabled Public Accessibility for RDS Instance '{resource_id}'.")
            return True
        except ClientError as e:
            self.logging.error(f"RDS Instance public access check failed for {resource_id}: {e}")
        except Exception as e:
            self.logging.error(f"Unexpected error in RDS public access check for {resource_id}: {e}")
        return False

    def s3_bucket_server_side_encryption_enabled(self, resource_id):
        """Enables Server-side Encryption for an S3 Bucket"""
        try:
            self.client_s3.put_bucket_encryption(
                Bucket=resource_id,
                ServerSideEncryptionConfiguration={
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                }
            )
            self.logging.info(f"Enabled Server-side Encryption for S3 Bucket '{resource_id}'.")
            return True
        except ClientError as e:
            self.logging.error(f"Failed to enable encryption on S3 Bucket '{resource_id}': {e}")
        except Exception as e:
            self.logging.error(f"Unexpected error enabling encryption on S3 Bucket '{resource_id}': {e}")
        return False

    def s3_bucket_ssl_requests_only(self, resource_id):
        """Adds Bucket Policy to force SSL-only connections"""
        policy_file = "auto_remediate/data/s3_bucket_ssl_requests_only_policy.json"
        try:
            with open(policy_file, "r") as file:
                policy = json.loads(file.read().replace("_BUCKET_", resource_id))
            response = self.client_s3.get_bucket_policy(Bucket=resource_id)
            existing_policy = json.loads(response["Policy"])
            existing_policy["Statement"].append(policy["Statement"][0])
            return self.set_bucket_policy(resource_id, json.dumps(existing_policy))
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return self.set_bucket_policy(resource_id, json.dumps(policy))
            self.logging.error(f"Failed to set SSL policy on S3 Bucket '{resource_id}': {e}")
        except Exception as e:
            self.logging.error(f"Unexpected error setting SSL policy on S3 Bucket '{resource_id}': {e}")
        return False

    def set_bucket_policy(self, bucket, policy):
        """Sets an S3 Bucket Policy, handling access issues"""
        try:
            self.client_s3.put_bucket_policy(Bucket=bucket, Policy=policy)
            self.logging.info(f"Set SSL requests-only policy to S3 Bucket '{bucket}'.")
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                try:
                    self.client_s3.put_public_access_block(
                        Bucket=bucket,
                        PublicAccessBlockConfiguration={
                            "BlockPublicPolicy": False,
                            "RestrictPublicBuckets": False
                        }
                    )
                    self.client_s3.put_bucket_policy(Bucket=bucket, Policy=policy)
                    self.client_s3.put_public_access_block(
                        Bucket=bucket,
                        PublicAccessBlockConfiguration={
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": True
                        }
                    )
                    self.logging.info(f"Set SSL requests-only policy to S3 Bucket '{bucket}'.")
                    return True
                except Exception as e:
                    self.logging.error(f"Failed to set SSL-only policy after access issue for '{bucket}': {e}")
            else:
                self.logging.error(f"Access issue setting policy on S3 Bucket '{bucket}': {e}")
        except Exception as e:
            self.logging.error(f"Unexpected error setting policy on S3 Bucket '{bucket}': {e}")
        return False
