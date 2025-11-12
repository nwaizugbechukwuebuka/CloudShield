"""
Secrets Management Module for CloudShield
Supports multiple backends: AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, and local .env
"""

import os
import json
from typing import Optional, Dict, Any
from enum import Enum
import boto3
from botocore.exceptions import ClientError
import hvac
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from src.api.utils.logger import get_logger
from src.api.utils.config import settings

logger = get_logger(__name__)


class SecretBackend(str, Enum):
    """Supported secret backends"""

    AWS_SECRETS_MANAGER = "aws_secrets_manager"
    HASHICORP_VAULT = "hashicorp_vault"
    AZURE_KEY_VAULT = "azure_key_vault"
    LOCAL_ENV = "local_env"


class SecretsManager:
    """
    Unified secrets management interface supporting multiple backends
    """

    def __init__(self, backend: SecretBackend = None):
        """
        Initialize secrets manager with specified backend

        Args:
            backend: SecretBackend enum value (defaults to settings.SECRET_BACKEND)
        """
        self.backend = backend or getattr(settings, "SECRET_BACKEND", SecretBackend.LOCAL_ENV)
        self._client = None
        self._cache: Dict[str, Any] = {}
        self._initialize_backend()

    def _initialize_backend(self):
        """Initialize the secrets backend client"""
        try:
            if self.backend == SecretBackend.AWS_SECRETS_MANAGER:
                self._client = boto3.client(
                    "secretsmanager",
                    region_name=getattr(settings, "AWS_REGION", "us-east-1"),
                )
                logger.info("Initialized AWS Secrets Manager backend")

            elif self.backend == SecretBackend.HASHICORP_VAULT:
                vault_addr = getattr(settings, "VAULT_ADDR", "http://localhost:8200")
                vault_token = os.getenv("VAULT_TOKEN")

                if not vault_token:
                    raise ValueError("VAULT_TOKEN environment variable not set")

                self._client = hvac.Client(url=vault_addr, token=vault_token)

                if not self._client.is_authenticated():
                    raise ValueError("Vault authentication failed")

                logger.info(f"Initialized HashiCorp Vault backend: {vault_addr}")

            elif self.backend == SecretBackend.AZURE_KEY_VAULT:
                vault_url = getattr(settings, "AZURE_KEY_VAULT_URL", "")
                if not vault_url:
                    raise ValueError("AZURE_KEY_VAULT_URL not configured")

                credential = DefaultAzureCredential()
                self._client = SecretClient(vault_url=vault_url, credential=credential)
                logger.info(f"Initialized Azure Key Vault backend: {vault_url}")

            elif self.backend == SecretBackend.LOCAL_ENV:
                logger.info("Using local environment variables for secrets")
            else:
                raise ValueError(f"Unsupported secret backend: {self.backend}")

        except Exception as e:
            logger.error(f"Failed to initialize secrets backend: {e}")
            logger.warning("Falling back to local environment variables")
            self.backend = SecretBackend.LOCAL_ENV
            self._client = None

    def get_secret(self, secret_name: str, default: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a secret from the configured backend

        Args:
            secret_name: Name/key of the secret
            default: Default value if secret not found

        Returns:
            Secret value or default
        """
        # Check cache first
        if secret_name in self._cache:
            return self._cache[secret_name]

        try:
            if self.backend == SecretBackend.AWS_SECRETS_MANAGER:
                value = self._get_aws_secret(secret_name)
            elif self.backend == SecretBackend.HASHICORP_VAULT:
                value = self._get_vault_secret(secret_name)
            elif self.backend == SecretBackend.AZURE_KEY_VAULT:
                value = self._get_azure_secret(secret_name)
            else:  # LOCAL_ENV
                value = os.getenv(secret_name, default)

            # Cache the value
            if value:
                self._cache[secret_name] = value

            return value

        except Exception as e:
            logger.error(f"Failed to retrieve secret '{secret_name}': {e}")
            return default

    def _get_aws_secret(self, secret_name: str) -> Optional[str]:
        """Retrieve secret from AWS Secrets Manager"""
        try:
            response = self._client.get_secret_value(SecretId=secret_name)

            # Secrets can be string or binary
            if "SecretString" in response:
                secret = response["SecretString"]
                # Try to parse as JSON
                try:
                    secret_dict = json.loads(secret)
                    # If it's a dict, return the first value (common pattern)
                    return list(secret_dict.values())[0] if secret_dict else secret
                except json.JSONDecodeError:
                    return secret
            else:
                # Binary secret
                return response["SecretBinary"].decode("utf-8")

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceNotFoundException":
                logger.warning(f"Secret '{secret_name}' not found in AWS Secrets Manager")
            elif error_code == "InvalidRequestException":
                logger.error(f"Invalid request for secret '{secret_name}'")
            elif error_code == "InvalidParameterException":
                logger.error(f"Invalid parameter for secret '{secret_name}'")
            else:
                logger.error(f"AWS Secrets Manager error: {e}")
            return None

    def _get_vault_secret(self, secret_name: str) -> Optional[str]:
        """Retrieve secret from HashiCorp Vault"""
        try:
            # Default KV v2 mount point
            mount_point = getattr(settings, "VAULT_MOUNT_POINT", "secret")
            path = getattr(settings, "VAULT_SECRET_PATH", "cloudshield")

            # Read secret from KV v2
            response = self._client.secrets.kv.v2.read_secret_version(
                path=f"{path}/{secret_name}", mount_point=mount_point
            )

            if response and "data" in response and "data" in response["data"]:
                secret_data = response["data"]["data"]
                # Return the value for the key that matches secret_name, or first value
                return secret_data.get("value") or secret_data.get(secret_name) or list(secret_data.values())[0]

            return None

        except Exception as e:
            logger.error(f"HashiCorp Vault error for '{secret_name}': {e}")
            return None

    def _get_azure_secret(self, secret_name: str) -> Optional[str]:
        """Retrieve secret from Azure Key Vault"""
        try:
            # Azure Key Vault secret names must use hyphens, not underscores
            azure_secret_name = secret_name.replace("_", "-")
            secret = self._client.get_secret(azure_secret_name)
            return secret.value

        except Exception as e:
            logger.error(f"Azure Key Vault error for '{secret_name}': {e}")
            return None

    def set_secret(self, secret_name: str, secret_value: str) -> bool:
        """
        Store a secret in the configured backend

        Args:
            secret_name: Name/key of the secret
            secret_value: Value to store

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.backend == SecretBackend.AWS_SECRETS_MANAGER:
                return self._set_aws_secret(secret_name, secret_value)
            elif self.backend == SecretBackend.HASHICORP_VAULT:
                return self._set_vault_secret(secret_name, secret_value)
            elif self.backend == SecretBackend.AZURE_KEY_VAULT:
                return self._set_azure_secret(secret_name, secret_value)
            else:
                logger.warning("Cannot set secrets with LOCAL_ENV backend")
                return False

        except Exception as e:
            logger.error(f"Failed to store secret '{secret_name}': {e}")
            return False

    def _set_aws_secret(self, secret_name: str, secret_value: str) -> bool:
        """Store secret in AWS Secrets Manager"""
        try:
            # Try to update existing secret
            self._client.update_secret(SecretId=secret_name, SecretString=secret_value)
            logger.info(f"Updated secret '{secret_name}' in AWS Secrets Manager")
            return True

        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                # Secret doesn't exist, create it
                try:
                    self._client.create_secret(Name=secret_name, SecretString=secret_value)
                    logger.info(f"Created secret '{secret_name}' in AWS Secrets Manager")
                    return True
                except Exception as create_error:
                    logger.error(f"Failed to create secret: {create_error}")
                    return False
            else:
                logger.error(f"AWS Secrets Manager error: {e}")
                return False

    def _set_vault_secret(self, secret_name: str, secret_value: str) -> bool:
        """Store secret in HashiCorp Vault"""
        try:
            mount_point = getattr(settings, "VAULT_MOUNT_POINT", "secret")
            path = getattr(settings, "VAULT_SECRET_PATH", "cloudshield")

            # Write secret to KV v2
            self._client.secrets.kv.v2.create_or_update_secret(
                path=f"{path}/{secret_name}",
                secret={"value": secret_value},
                mount_point=mount_point,
            )

            logger.info(f"Stored secret '{secret_name}' in HashiCorp Vault")
            return True

        except Exception as e:
            logger.error(f"HashiCorp Vault error: {e}")
            return False

    def _set_azure_secret(self, secret_name: str, secret_value: str) -> bool:
        """Store secret in Azure Key Vault"""
        try:
            azure_secret_name = secret_name.replace("_", "-")
            self._client.set_secret(azure_secret_name, secret_value)
            logger.info(f"Stored secret '{secret_name}' in Azure Key Vault")
            return True

        except Exception as e:
            logger.error(f"Azure Key Vault error: {e}")
            return False

    def rotate_secret(self, secret_name: str, new_value: str) -> bool:
        """
        Rotate a secret by updating its value

        Args:
            secret_name: Name of the secret to rotate
            new_value: New secret value

        Returns:
            True if successful
        """
        success = self.set_secret(secret_name, new_value)
        if success:
            # Clear from cache to force refresh
            self._cache.pop(secret_name, None)
            logger.info(f"Rotated secret '{secret_name}'")
        return success

    def clear_cache(self):
        """Clear the secrets cache"""
        self._cache.clear()
        logger.debug("Secrets cache cleared")


# Global secrets manager instance
secrets_manager = SecretsManager()


def get_secret(secret_name: str, default: Optional[str] = None) -> Optional[str]:
    """
    Convenience function to get a secret

    Args:
        secret_name: Name of the secret
        default: Default value if not found

    Returns:
        Secret value or default
    """
    return secrets_manager.get_secret(secret_name, default)


def set_secret(secret_name: str, secret_value: str) -> bool:
    """
    Convenience function to set a secret

    Args:
        secret_name: Name of the secret
        secret_value: Value to store

    Returns:
        True if successful
    """
    return secrets_manager.set_secret(secret_name, secret_value)


# Example usage in application code:
# from src.api.utils.secrets import get_secret
#
# database_password = get_secret("DATABASE_PASSWORD")
# jwt_secret = get_secret("JWT_SECRET_KEY")
# oauth_client_secret = get_secret("GOOGLE_OAUTH_CLIENT_SECRET")
