import asyncio
import json
from contextlib import asynccontextmanager
from sys import prefix
from time import sleep
from datetime import datetime
import os
import re
import yaml
from urllib.parse import unquote, urlparse, urlunparse
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from elastic_transport import TransportError
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from httpx import AsyncClient
from elasticsearch import AsyncElasticsearch
import uvicorn
from pydantic import BaseModel, validator
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pandas as pd
import numpy as np
from dataclasses import dataclass, field
import uuid
import redis.asyncio as aioredis
import pickle
import hashlib
#ehab
import ssl
import logging
import sys
import time
from dotenv import load_dotenv
from certbot import main as certbot_main
import ctypes
import subprocess
import shutil
import OpenSSL
import tempfile
import socket
import fileinput
import functools
import threading
#ehab

#import model_prediction as model

#ehab################################################################################################################
# # Load environment variables from .env file
# load_dotenv(".env")
#
#
#
#
# # Models for certificate management
# class CertificateConfig(BaseModel):
#     domain_name: str
#     email: str
#     duckdns_token: str
#     auto_renewal: bool = True
#     renewal_interval_hours: int = 24
#
# class CertificateStatus(BaseModel):
#     domain: str
#     exists: bool
#     valid: bool
#     expiry_date: Optional[str] = None
#     days_until_expiry: Optional[int] = None
#     certificate_path: str
#     key_path: str
#     size_bytes: Optional[int] = None
#     last_modified: Optional[str] = None
#
#
#
# class CertificateInfo(BaseModel):
#     subject: str
#     issuer: str
#     not_before: str
#     not_after: str
#     serial_number: str
#     signature_algorithm: str
#     key_size: Optional[int] = None
#
# # New models for dynamic certificate creation
# class CertificateCreationRequest(BaseModel):
#     domain_name: str
#     email: str
#     duckdns_token: str
#     auto_renewal: bool = True
#     renewal_interval_hours: int = 24
#     force_renewal: bool = False
#
# class CertificateValidationRequest(BaseModel):
#     domain_name: str
#     duckdns_token: str
#
# class CertificateValidationResponse(BaseModel):
#     domain_valid: bool
#     token_valid: bool
#     domain_available: bool
#     message: str
#     details: Optional[Dict[str, Any]] = None
#
# class CertificateOperationResponse(BaseModel):
#     success: bool
#     message: str
#     operation_id: Optional[str] = None
#     status: Optional[CertificateStatus] = None
#     logs: Optional[List[str]] = None
#
#
#
#
# # ------------------------------------------------------------
# # Utility Functions
# # ------------------------------------------------------------
#
# def is_admin():
#     """Check if the script is running with administrative privileges."""
#     try:
#         return ctypes.windll.shell32.IsUserAnAdmin()
#     except:
#         return False
#
# def run_as_admin():
#     """Relaunch the script with administrative privileges."""
#     if os.name == 'nt' and not is_admin():
#         # Create a temporary VBS script to handle UAC elevation
#         vbs_script = os.path.join(tempfile.gettempdir(), 'elevate.vbs')
#         with open(vbs_script, 'w') as f:
#             f.write(f'''
# Set objShell = CreateObject("Shell.Application")
# objShell.ShellExecute "{sys.executable}", "{" ".join(sys.argv)}", "", "runas", 1
# ''')
#
#         try:
#             # Run the VBS script
#             subprocess.run(['cscript', '//nologo', vbs_script],
#                          creationflags=subprocess.CREATE_NO_WINDOW)
#             # Exit the current process
#             sys.exit(0)
#         finally:
#             # Clean up the VBS script
#             try:
#                 os.remove(vbs_script)
#             except:
#                 pass
#
# # Attempt to elevate privileges at startup
# run_as_admin()  # Enable automatic privilege elevation at startup
#
# # Let's Encrypt Configuration
# LETSENCRYPT_EMAIL = os.getenv("LETSENCRYPT_EMAIL", "ahmed4ehab@gmail.com")
# DOMAIN_NAME = os.getenv("DOMAIN_NAME", "shelby1.duckdns.org")
# DUCK_DNS_TOKEN = os.getenv("DUCK_DNS_TOKEN", "49f13a70-e08e-45d5-bd32-e9eaf7b3f1ab")
#
# # Get the directory where this script is located
# SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# CERT_DIR = os.getenv("CERT_DIR", os.path.join(SCRIPT_DIR, "letsencrypt"))
# CERT_PATH = os.path.join(CERT_DIR, DOMAIN_NAME)
#
# # SSL/TLS Configuration - certificates will be saved in the script directory
# SSL_CERT_FILE = os.path.join(SCRIPT_DIR, "fullchain.pem")
# SSL_KEY_FILE = os.path.join(SCRIPT_DIR, "privkey.pem")
# ES_CA_CERT = os.getenv("ES_CA_CERT", "C:/Windows/System32/certificates/ca-certificates.crt")
#
# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(levelname)s - %(message)s'
# )
# logger = logging.getLogger(__name__)
#
#
#
# def get_temp_cert_dir():
#     """Get a temporary directory for certificate generation."""
#     temp_dir = os.path.join(os.environ.get('TEMP', os.path.dirname(os.path.abspath(__file__))),
#                            f'certbot_temp_{int(time.time())}')
#     os.makedirs(temp_dir, exist_ok=True)
#     os.makedirs(os.path.join(temp_dir, 'logs'), exist_ok=True)
#     os.makedirs(os.path.join(temp_dir, 'work'), exist_ok=True)
#     os.makedirs(os.path.join(temp_dir, 'live'), exist_ok=True)
#     return temp_dir
#
# def kill_certbot_processes():
#     """Kill any running Certbot processes."""
#     try:
#         if sys.platform == 'win32':
#             # Kill all Python processes that might be running certbot
#             subprocess.run(['taskkill', '/F', '/IM', 'python.exe', '/FI', 'WINDOWTITLE eq certbot*'],
#                          creationflags=subprocess.CREATE_NO_WINDOW)
#             subprocess.run(['taskkill', '/F', '/IM', 'python.exe', '/FI', 'WINDOWTITLE eq python*'],
#                          creationflags=subprocess.CREATE_NO_WINDOW)
#             subprocess.run(['taskkill', '/F', '/IM', 'certbot.exe'],
#                          creationflags=subprocess.CREATE_NO_WINDOW)
#
#             # Kill any processes using the certbot directories
#             for dir_path in [CERT_DIR, os.path.join(CERT_DIR, 'logs'),
#                            os.path.join(CERT_DIR, 'work'), os.path.join(CERT_DIR, 'live')]:
#                 try:
#                     subprocess.run(['taskkill', '/F', '/IM', 'python.exe', '/FI', f'MODULES eq {dir_path}'],
#                                  creationflags=subprocess.CREATE_NO_WINDOW)
#                 except:
#                     pass
#         else:
#             subprocess.run(['pkill', '-f', 'certbot'])
#     except Exception as e:
#         logger.warning(f"Error killing Certbot processes: {e}")
#
# def cleanup_certbot_locks():
#     """Clean up any existing certbot processes and lock files."""
#     try:
#         # Kill any running certbot processes
#         subprocess.run(['taskkill', '/F', '/IM', 'certbot.exe'],
#                       creationflags=subprocess.CREATE_NO_WINDOW)
#
#         # Wait for processes to terminate
#         time.sleep(1)
#
#         # Remove lock files
#         lock_files = [
#             os.path.join(CERT_DIR, 'logs', '.certbot.lock'),
#             os.path.join(CERT_DIR, 'work', '.certbot.lock'),
#             os.path.join(CERT_DIR, 'live', '.certbot.lock'),
#             os.path.join(CERT_DIR, 'logs', 'letsencrypt.log'),
#             os.path.join(CERT_DIR, 'work', 'letsencrypt.log'),
#             os.path.join(CERT_DIR, 'live', 'letsencrypt.log')
#         ]
#
#         for lock_file in lock_files:
#             try:
#                 if os.path.exists(lock_file):
#                     os.remove(lock_file)
#                     logger.info(f"Removed lock file: {lock_file}")
#             except Exception as e:
#                 logger.warning(f"Error removing lock file {lock_file}: {e}")
#
#     except Exception as e:
#         logger.error(f"Error cleaning up certbot processes: {e}")
#
#
#
# # Certificate management functions
# def get_certificate_info(cert_path: str) -> Optional[CertificateInfo]:
#     """Extract certificate information from PEM file."""
#     try:
#         if not os.path.exists(cert_path):
#             return None
#
#         with open(cert_path, 'rb') as f:
#             cert_data = f.read()
#
#         cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
#
#         # Get key size if possible
#         key_size = None
#         try:
#             pubkey = cert.get_pubkey()
#             key_size = pubkey.bits()
#         except:
#             pass
#
#         return CertificateInfo(
#             subject=cert.get_subject().CN or cert.get_subject().commonName or "Unknown",
#             issuer=cert.get_issuer().CN or cert.get_issuer().commonName or "Unknown",
#             not_before=cert.get_notBefore().decode('utf-8'),
#             not_after=cert.get_notAfter().decode('utf-8'),
#             serial_number=str(cert.get_serial_number()),
#             signature_algorithm=cert.get_signature_algorithm().decode('utf-8'),
#             key_size=key_size
#         )
#     except Exception as e:
#         logger.error(f"Error reading certificate info: {e}")
#         return None
#
# def check_certificate_status(domain: str = None) -> CertificateStatus:
#     """Check the status of SSL certificates."""
#     if domain is None:
#         domain = DOMAIN_NAME
#
#     # For domain-specific certificates, look in the domain-specific directory
#     if domain != DOMAIN_NAME:
#         cert_path = os.path.join(CERT_DIR, 'live', domain, 'fullchain.pem')
#         key_path = os.path.join(CERT_DIR, 'live', domain, 'privkey.pem')
#     else:
#         # For the primary domain, use the main SSL paths
#         cert_path = SSL_CERT_FILE
#         key_path = SSL_KEY_FILE
#
#     exists = os.path.exists(cert_path) and os.path.exists(key_path)
#     valid = False
#     expiry_date = None
#     days_until_expiry = None
#     size_bytes = None
#     last_modified = None
#
#     if exists:
#         try:
#             # Check file sizes
#             size_bytes = os.path.getsize(cert_path)
#
#             # Check last modified
#             last_modified = datetime.fromtimestamp(os.path.getmtime(cert_path)).isoformat()
#
#             # Get certificate info
#             cert_info = get_certificate_info(cert_path)
#             if cert_info:
#                 valid = True
#                 expiry_date = cert_info.not_after
#
#                 # Calculate days until expiry
#                 try:
#                     expiry_datetime = datetime.strptime(expiry_date, '%Y%m%d%H%M%SZ')
#                     days_until_expiry = (expiry_datetime - datetime.now()).days
#                 except:
#                     pass
#         except Exception as e:
#             logger.error(f"Error checking certificate status: {e}")
#
#     return CertificateStatus(
#         domain=domain,
#         exists=exists,
#         valid=valid,
#         expiry_date=expiry_date,
#         days_until_expiry=days_until_expiry,
#         certificate_path=cert_path,
#         key_path=key_path,
#         size_bytes=size_bytes,
#         last_modified=last_modified
#     )
#
# def validate_certificate_config(config: CertificateConfig) -> bool:
#     """Validate certificate configuration."""
#     try:
#         # Validate domain name
#         if not config.domain_name or '.' not in config.domain_name:
#             return False
#
#         # Validate email
#         if not config.email or '@' not in config.email:
#             return False
#
#         # Validate DuckDNS token (basic check)
#         if not config.duckdns_token or len(config.duckdns_token) < 10:
#             return False
#
#         # Validate renewal interval
#         if config.renewal_interval_hours < 1 or config.renewal_interval_hours > 8760:  # Max 1 year
#             return False
#
#         return True
#     except Exception as e:
#         logger.error(f"Error validating certificate config: {e}")
#         return False
#
# def update_certificate_config(config: CertificateConfig) -> bool:
#     """Update certificate configuration."""
#     try:
#         if not validate_certificate_config(config):
#             return False
#
#         # Update environment variables
#         os.environ["DOMAIN_NAME"] = config.domain_name
#         os.environ["LETSENCRYPT_EMAIL"] = config.email
#         os.environ["DUCK_DNS_TOKEN"] = config.duckdns_token
#
#         # Update global variables
#         global DOMAIN_NAME, LETSENCRYPT_EMAIL, DUCK_DNS_TOKEN
#         DOMAIN_NAME = config.domain_name
#         LETSENCRYPT_EMAIL = config.email
#         DUCK_DNS_TOKEN = config.duckdns_token
#
#         # Save configuration to a file for persistence
#         config_data = {
#             "domain_name": config.domain_name,
#             "email": config.email,
#             "duckdns_token": config.duckdns_token,
#             "auto_renewal": config.auto_renewal,
#             "renewal_interval_hours": config.renewal_interval_hours
#         }
#
#         config_file = os.path.join(SCRIPT_DIR, "cert_config.json")
#         with open(config_file, 'w') as f:
#             json.dump(config_data, f, indent=2)
#
#         logger.info(f"Certificate configuration updated for domain: {config.domain_name}")
#         return True
#     except Exception as e:
#         logger.error(f"Error updating certificate config: {e}")
#         return False
#
# def load_certificate_config() -> Optional[CertificateConfig]:
#     """Load certificate configuration from file."""
#     try:
#         config_file = os.path.join(SCRIPT_DIR, "cert_config.json")
#         if os.path.exists(config_file):
#             with open(config_file, 'r') as f:
#                 config_data = json.load(f)
#
#             return CertificateConfig(**config_data)
#         else:
#             # Return default config based on environment variables
#             return CertificateConfig(
#                 domain_name=DOMAIN_NAME,
#                 email=LETSENCRYPT_EMAIL,
#                 duckdns_token=DUCK_DNS_TOKEN,
#                 auto_renewal=True,
#                 renewal_interval_hours=24
#             )
#     except Exception as e:
#         logger.error(f"Error loading certificate config: {e}")
#         return None
#
# def delete_certificates(domain: str = None) -> bool:
#     """Delete SSL certificates for a domain."""
#     try:
#         if domain is None:
#             domain = DOMAIN_NAME
#
#         # Delete certificate files
#         cert_path = SSL_CERT_FILE
#         key_path = SSL_KEY_FILE
#
#         deleted_files = []
#
#         if os.path.exists(cert_path):
#             os.remove(cert_path)
#             deleted_files.append(cert_path)
#
#         if os.path.exists(key_path):
#             os.remove(key_path)
#             deleted_files.append(key_path)
#
#         # Clean up certbot directories
#         domain_cert_dir = os.path.join(CERT_DIR, 'live', domain)
#         if os.path.exists(domain_cert_dir):
#             shutil.rmtree(domain_cert_dir)
#             deleted_files.append(domain_cert_dir)
#
#         logger.info(f"Deleted certificates for domain {domain}: {deleted_files}")
#         return True
#     except Exception as e:
#         logger.error(f"Error deleting certificates: {e}")
#         return False
#
# def test_duckdns_connection(token: str, domain: str = None) -> bool:
#     """Test DuckDNS API connection."""
#     try:
#         # Use the actual domain if provided, otherwise use a test domain
#         test_domain = domain if domain else "test"
#         url = f"https://www.duckdns.org/update?domains={test_domain}&token={token}&ip=127.0.0.1"
#         response = requests.get(url, timeout=10)
#         return response.status_code == 200 and "OK" in response.text
#     except Exception as e:
#         logger.error(f"Error testing DuckDNS connection: {e}")
#         return False
#
# def get_certificate_logs() -> List[Dict[str, Any]]:
#     """Get certificate-related logs."""
#     logs = []
#
#     try:
#         # Check certbot logs
#         log_files = [
#             os.path.join(CERT_DIR, 'logs', 'letsencrypt.log'),
#             os.path.join(CERT_DIR, 'logs', 'certbot.log')
#         ]
#
#         for log_file in log_files:
#             if os.path.exists(log_file):
#                 try:
#                     with open(log_file, 'r') as f:
#                         content = f.read()
#                         logs.append({
#                             "file": log_file,
#                             "content": content,
#                             "last_modified": datetime.fromtimestamp(os.path.getmtime(log_file)).isoformat(),
#                             "size": os.path.getsize(log_file)
#                         })
#                 except Exception as e:
#                     logger.error(f"Error reading log file {log_file}: {e}")
#
#         # Check for temporary certbot logs
#         temp_dirs = [d for d in os.listdir(os.environ.get('TEMP', os.path.dirname(os.path.abspath(__file__))))
#                     if d.startswith('certbot_temp_')]
#
#         for temp_dir in temp_dirs[-5:]:  # Only last 5 temp directories
#             temp_path = os.path.join(os.environ.get('TEMP', os.path.dirname(os.path.abspath(__file__))), temp_dir)
#             if os.path.exists(temp_path):
#                 for log_file in ['certbot_debug.log', 'certbot_error.log']:
#                     log_path = os.path.join(temp_path, log_file)
#                     if os.path.exists(log_path):
#                         try:
#                             with open(log_path, 'r') as f:
#                                 content = f.read()
#                                 logs.append({
#                                     "file": f"{temp_dir}/{log_file}",
#                                     "content": content,
#                                     "last_modified": datetime.fromtimestamp(os.path.getmtime(log_path)).isoformat(),
#                                     "size": os.path.getsize(log_path)
#                                 })
#                         except Exception as e:
#                             logger.error(f"Error reading temp log file {log_path}: {e}")
#
#     except Exception as e:
#         logger.error(f"Error getting certificate logs: {e}")
#
#     return logs
#
#
# # New functions for dynamic certificate management
# def validate_certificate_creation_request(request: CertificateCreationRequest) -> CertificateValidationResponse:
#     """Validate certificate creation request parameters."""
#     try:
#         # Validate domain name
#         domain_valid = bool(request.domain_name and '.' in request.domain_name and 'duckdns.org' in request.domain_name)
#
#         # Validate email
#         email_valid = bool(request.email and '@' in request.email and '.' in request.email.split('@')[1])
#
#         # Validate DuckDNS token
#         token_valid = bool(request.duckdns_token and len(request.duckdns_token) >= 10)
#
#         # Test DuckDNS connection if token is valid
#         domain_available = False
#         if token_valid:
#             domain_available = test_duckdns_connection(request.duckdns_token, request.domain_name)
#
#         # Determine overall validation result
#         overall_valid = domain_valid and email_valid and token_valid and domain_available
#
#         message = "Validation successful" if overall_valid else "Validation failed"
#         if not domain_valid:
#             message = "Invalid domain name (must be a valid DuckDNS domain)"
#         elif not email_valid:
#             message = "Invalid email address"
#         elif not token_valid:
#             message = "Invalid DuckDNS token"
#         elif not domain_available:
#             message = "DuckDNS connection failed or domain not available"
#
#         return CertificateValidationResponse(
#             domain_valid=domain_valid,
#             token_valid=token_valid,
#             domain_available=domain_available,
#             message=message,
#             details={
#                 "domain_name": request.domain_name,
#                 "email": request.email,
#                 "duckdns_token_length": len(request.duckdns_token) if request.duckdns_token else 0
#             }
#         )
#
#     except Exception as e:
#         logger.error(f"Error validating certificate creation request: {e}")
#         return CertificateValidationResponse(
#             domain_valid=False,
#             token_valid=False,
#             domain_available=False,
#             message=f"Validation error: {str(e)}"
#         )
#
# def setup_letsencrypt_dynamic(domain_name: str, email: str, duckdns_token: str, force_renewal: bool = False) -> CertificateOperationResponse:
#     """Set up SSL certificates using Let's Encrypt with dynamic parameters."""
#     operation_id = f"cert_op_{int(time.time())}"
#     logs = []
#
#     try:
#         logger.info(f"Starting dynamic Let's Encrypt setup for domain: {domain_name}")
#         logs.append(f"Starting certificate setup for domain: {domain_name}")
#
#         # Validate input parameters
#         validation_request = CertificateCreationRequest(
#             domain_name=domain_name,
#             email=email,
#             duckdns_token=duckdns_token
#         )
#         validation = validate_certificate_creation_request(validation_request)
#
#         if not (validation.domain_valid and validation.token_valid and validation.domain_available):
#             return CertificateOperationResponse(
#                 success=False,
#                 message=f"Validation failed: {validation.message}",
#                 operation_id=operation_id,
#                 logs=logs
#             )
#
#         # Create domain-specific certificate directory
#         domain_cert_dir = os.path.join(CERT_DIR, 'live', domain_name)
#         domain_work_dir = os.path.join(CERT_DIR, 'work', domain_name)
#         domain_logs_dir = os.path.join(CERT_DIR, 'logs', domain_name)
#
#         # Create directories
#         for dir_path in [domain_cert_dir, domain_work_dir, domain_logs_dir]:
#             try:
#                 os.makedirs(dir_path, exist_ok=True)
#                 logs.append(f"Created directory: {dir_path}")
#             except Exception as e:
#                 error_msg = f"Failed to create directory {dir_path}: {e}"
#                 logger.error(error_msg)
#                 logs.append(error_msg)
#                 return CertificateOperationResponse(
#                     success=False,
#                     message=error_msg,
#                     operation_id=operation_id,
#                     logs=logs
#                 )
#
#         # Check if certificates already exist and are valid
#         domain_cert_path = os.path.join(domain_cert_dir, 'fullchain.pem')
#         domain_key_path = os.path.join(domain_cert_dir, 'privkey.pem')
#
#         if (os.path.exists(domain_cert_path) and
#             os.path.exists(domain_key_path) and
#             os.path.getsize(domain_cert_path) > 0 and
#             os.path.getsize(domain_key_path) > 0 and
#             not force_renewal):
#
#             logs.append("SSL certificates found and valid, skipping setup")
#             return CertificateOperationResponse(
#                 success=True,
#                 message="Certificates already exist and are valid",
#                 operation_id=operation_id,
#                 status=check_certificate_status(domain_name),
#                 logs=logs
#             )
#
#         # Check if running as admin
#         if not is_admin():
#             error_msg = "SSL certificate setup requires administrative privileges"
#             logs.append(error_msg)
#             return CertificateOperationResponse(
#                 success=False,
#                 message=error_msg,
#                 operation_id=operation_id,
#                 logs=logs
#             )
#
#         # Clean up any existing certbot processes
#         cleanup_certbot_locks()
#         logs.append("Cleaned up existing certbot processes")
#
#         # Create DuckDNS credentials file
#         duckdns_creds = os.path.join(CERT_DIR, f'duckdns_{domain_name}.ini')
#         try:
#             with open(duckdns_creds, 'w') as f:
#                 f.write(f'''dns_duckdns_token = {duckdns_token}
# dns_duckdns_propagation_seconds = 60
# ''')
#             logs.append(f"Created DuckDNS credentials file for {domain_name}")
#         except Exception as e:
#             error_msg = f"Failed to create DuckDNS credentials file: {e}"
#             logger.error(error_msg)
#             logs.append(error_msg)
#             return CertificateOperationResponse(
#                 success=False,
#                 message=error_msg,
#                 operation_id=operation_id,
#                 logs=logs
#             )
#
#         # Run certbot with DNS challenge
#         certbot_cmd = [
#             'certbot',
#             'certonly',
#             '--non-interactive',
#             '--agree-tos',
#             '--email', email,
#             '--authenticator', 'dns-duckdns',
#             '--dns-duckdns-credentials', duckdns_creds,
#             '--dns-duckdns-propagation-seconds', '60',
#             '-d', domain_name,
#             '--config-dir', CERT_DIR,
#             '--work-dir', domain_work_dir,
#             '--logs-dir', domain_logs_dir,
#             '--preferred-challenges', 'dns',
#             '--debug'
#         ]
#
#         if force_renewal:
#             certbot_cmd.append('--force-renewal')
#
#         logs.append(f"Running certbot command: {' '.join(certbot_cmd)}")
#
#         process = subprocess.run(
#             certbot_cmd,
#             capture_output=True,
#             text=True,
#             creationflags=subprocess.CREATE_NO_WINDOW
#         )
#
#         # Log certbot output
#         logs.append("Certbot output:")
#         logs.append(process.stdout)
#         if process.stderr:
#             logs.append("Certbot errors:")
#             logs.append(process.stderr)
#
#         if process.returncode != 0:
#             error_msg = f"Certbot failed with return code {process.returncode}"
#             logs.append(error_msg)
#
#             # Check for specific error types
#             if "rateLimited" in process.stderr or "too many certificates" in process.stderr:
#                 error_msg = "Let's Encrypt rate limit reached! You have already requested 5 certificates for this domain in the last 7 days."
#                 logs.append(error_msg)
#
#             return CertificateOperationResponse(
#                 success=False,
#                 message=error_msg,
#                 operation_id=operation_id,
#                 logs=logs
#             )
#
#         # Wait for files to be created (up to 10 seconds)
#         max_wait = 10
#         wait_time = 0
#         while wait_time < max_wait:
#             if os.path.exists(domain_cert_path) and os.path.exists(domain_key_path):
#                 break
#             time.sleep(1)
#             wait_time += 1
#             logs.append(f"Waiting for certificate files... ({wait_time}s)")
#
#         if not os.path.exists(domain_cert_path) or not os.path.exists(domain_key_path):
#             error_msg = f"Certificate files not found after {max_wait} seconds"
#             logs.append(error_msg)
#             return CertificateOperationResponse(
#                 success=False,
#                 message=error_msg,
#                 operation_id=operation_id,
#                 logs=logs
#             )
#
#         # Copy certificates to application directory (if this is the primary domain)
#         if domain_name == DOMAIN_NAME:
#             try:
#                 shutil.copy2(domain_cert_path, SSL_CERT_FILE)
#                 shutil.copy2(domain_key_path, SSL_KEY_FILE)
#                 logs.append(f"SSL certificates copied to application directory")
#             except Exception as e:
#                 error_msg = f"Failed to copy certificate files: {e}"
#                 logger.error(error_msg)
#                 logs.append(error_msg)
#                 # Don't fail the operation, just log the warning
#
#         logs.append("SSL certificates successfully obtained and installed")
#
#         # Get final status
#         final_status = check_certificate_status(domain_name)
#
#         return CertificateOperationResponse(
#             success=True,
#             message="SSL certificates successfully obtained and installed",
#             operation_id=operation_id,
#             status=final_status,
#             logs=logs
#         )
#
#     except Exception as e:
#         error_msg = f"Error setting up SSL certificates: {e}"
#         logger.error(error_msg)
#         logs.append(error_msg)
#         return CertificateOperationResponse(
#             success=False,
#             message=error_msg,
#             operation_id=operation_id,
#             logs=logs
#         )
#
# def renew_certificates_dynamic(domain_name: str, email: str, duckdns_token: str, force: bool = False) -> CertificateOperationResponse:
#     """Renew SSL certificates with dynamic parameters."""
#     return setup_letsencrypt_dynamic(domain_name, email, duckdns_token, force_renewal=force)
#
# def delete_certificates_dynamic(domain_name: str) -> CertificateOperationResponse:
#     """Delete SSL certificates for a specific domain."""
#     operation_id = f"cert_delete_{int(time.time())}"
#     logs = []
#
#     try:
#         logs.append(f"Starting certificate deletion for domain: {domain_name}")
#
#         # Delete domain-specific certificate files
#         domain_cert_dir = os.path.join(CERT_DIR, 'live', domain_name)
#         domain_cert_path = os.path.join(domain_cert_dir, 'fullchain.pem')
#         domain_key_path = os.path.join(domain_cert_dir, 'privkey.pem')
#
#         deleted_files = []
#
#         if os.path.exists(domain_cert_path):
#             os.remove(domain_cert_path)
#             deleted_files.append(domain_cert_path)
#             logs.append(f"Deleted certificate file: {domain_cert_path}")
#
#         if os.path.exists(domain_key_path):
#             os.remove(domain_key_path)
#             deleted_files.append(domain_key_path)
#             logs.append(f"Deleted key file: {domain_key_path}")
#
#         # Clean up certbot directories
#         if os.path.exists(domain_cert_dir):
#             shutil.rmtree(domain_cert_dir)
#             deleted_files.append(domain_cert_dir)
#             logs.append(f"Deleted certificate directory: {domain_cert_dir}")
#
#         # If this is the primary domain, also delete the main certificate files
#         if domain_name == DOMAIN_NAME:
#             if os.path.exists(SSL_CERT_FILE):
#                 os.remove(SSL_CERT_FILE)
#                 deleted_files.append(SSL_CERT_FILE)
#                 logs.append(f"Deleted main certificate file: {SSL_CERT_FILE}")
#
#             if os.path.exists(SSL_KEY_FILE):
#                 os.remove(SSL_KEY_FILE)
#                 deleted_files.append(SSL_KEY_FILE)
#                 logs.append(f"Deleted main key file: {SSL_KEY_FILE}")
#
#         logs.append(f"Successfully deleted {len(deleted_files)} files/directories")
#
#         return CertificateOperationResponse(
#             success=True,
#             message=f"Certificates deleted successfully for domain: {domain_name}",
#             operation_id=operation_id,
#             logs=logs
#         )
#
#     except Exception as e:
#         error_msg = f"Error deleting certificates: {e}"
#         logger.error(error_msg)
#         logs.append(error_msg)
#         return CertificateOperationResponse(
#             success=False,
#             message=error_msg,
#             operation_id=operation_id,
#             logs=logs
#         )
#

#ehab################################################################################################################



# Define rule types as enum for better type safety
class RuleType(str, Enum):
    SECURITY_PATTERN = "security-pattern"
    HEADER_MANIPULATION = "header-manipulation"
    SESSION_MANAGEMENT = "session-management"

class ActionType(str, Enum):
    BLOCK = "block"
    ALLOW = "allow"
    ALERT = "alert"

@dataclass
class RuleMatch:
    rule_id: str
    rule: dict
    priority: int
    
    def __lt__(self, other):
        return self.priority > other.priority  # Higher priority first

def get_rule_priority(rule: dict) -> int:
    """
    Calculate rule priority based on severity and action.
    Higher number = higher priority.
    Priority order: BLOCK > ALERT
    Severity order: critical > high > medium > low
    """
    # Action priority (higher = more important)
    action_priority = {
        "block": 100,
        "alert": 80
    }
    
    # Severity priority (higher = more important)
    severity_priority = {
        "critical": 10,
        "high": 8,
        "medium": 6,
        "low": 4
    }
    
    action = rule.get("action", "block")
    severity = rule.get("severity", "medium")
    
    base_priority = action_priority.get(action, 0)
    severity_bonus = severity_priority.get(severity, 0)
    
    return base_priority + severity_bonus

# Models for rule management
class Rule(BaseModel):
    id: str
    type: RuleType
    subtype: Optional[str] = None  # Only used for header-manipulation and session-management rules
    pattern: Optional[str] = None
    header_name: Optional[str] = None
    header_value: Optional[str] = None
    description: Optional[str] = None
    severity: str = "medium"
    action: ActionType = ActionType.BLOCK
    enabled: bool = True
    # Session-specific parameters
    max_requests: Optional[int] = None
    max_blocked: Optional[int] = None
    block_duration: Optional[int] = None
    time_window: Optional[int] = None  # Time window in seconds for session management rules
    # IP-based header manipulation
    suspicious_ips: Optional[List[str]] = None
    
    @validator('subtype')
    def validate_subtype(cls, v, values):
        """Validate that subtype is provided for header-manipulation and session-management rules"""
        rule_type = values.get('type')
        if rule_type in [RuleType.HEADER_MANIPULATION, RuleType.SESSION_MANAGEMENT]:
            if not v:
                raise ValueError(f"subtype is required for {rule_type} rules")
        elif rule_type == RuleType.SECURITY_PATTERN and v:
            # Warn that subtype is not used for security-pattern rules
            print(f"Warning: subtype '{v}' is not used for security-pattern rules")
        return v

class RuleUpdate(BaseModel):
    type: Optional[RuleType] = None
    subtype: Optional[str] = None
    pattern: Optional[str] = None
    header_name: Optional[str] = None
    header_value: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    action: Optional[ActionType] = None
    enabled: Optional[bool] = None
    # Session-specific parameters
    max_requests: Optional[int] = None
    max_blocked: Optional[int] = None
    block_duration: Optional[int] = None
    time_window: Optional[int] = None  # Time window in seconds for session management rules
    # IP-based header manipulation
    suspicious_ips: Optional[List[str]] = None

class Policy(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    rules: List[str]  # List of rule IDs
    enabled: bool = True

class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rules: Optional[List[str]] = None
    enabled: Optional[bool] = None

# Define a custom representer that tells PyYAML to dump the Enum as its value.
def enum_representer(dumper, data):
    return dumper.represent_data(data.value)

# Register the representer for your enums.
yaml.add_representer(RuleType, enum_representer)
yaml.add_representer(ActionType, enum_representer)

# Main application
app = FastAPI(title="Smart Web Application Firewall")

# Enable CORS for admin UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
RULES_FILE = "rules.yaml"
POLICIES_FILE = "policies.yaml"

# ------------------------------------------------------------
# Session Data Model
# ------------------------------------------------------------
@dataclass
class SessionData:
    domain: str
    user_agent: str
    request_count: int = 0
    blocked_count: int = 0
    last_seen: datetime = field(default_factory=datetime.utcnow)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None  # Track when session was explicitly ended
    ip_address: str = ""
    blocked_requests: List[Dict] = field(default_factory=list)
    attack_patterns: Dict[str, int] = field(default_factory=dict)
    request_patterns: Dict[str, int] = field(default_factory=dict)
    request_timestamps: List[datetime] = field(default_factory=list)  # Track request timestamps for rolling window

SESSION_TTL = 300  # seconds

# ------------------------------------------------------------
# Helper functions for session duration calculation
# ------------------------------------------------------------
def calculate_session_duration(sess: SessionData) -> tuple[float, str, str]:
    """
    Calculate accurate session duration considering request timestamps and session end state.
    Returns: (duration_minutes, idle_str, session_status)
    """
    now = datetime.utcnow()
    
    # Determine the "end" of session for length calculation
    if sess.ended_at:
        # Session was explicitly ended
        end_time = sess.ended_at
        session_status = "ENDED"
    elif sess.request_timestamps:
        # Use the latest request timestamp as last activity
        last_activity = max(sess.request_timestamps)
        # If session is still active (within TTL), use current time
        time_since_last = (now - last_activity).total_seconds()
        if time_since_last <= SESSION_TTL:
            end_time = now
            session_status = "ACTIVE"
        else:
            end_time = last_activity
            session_status = "IDLE"
    else:
        # Fallback to last_seen
        last_activity = sess.last_seen
        time_since_last = (now - last_activity).total_seconds()
        if time_since_last <= SESSION_TTL:
            end_time = now
            session_status = "ACTIVE"
        else:
            end_time = last_activity
            session_status = "IDLE"
    
    # Calculate duration
    duration = end_time - sess.first_seen
    duration_minutes = duration.total_seconds() / 60
    
    # Calculate idle time (time since last activity)
    if sess.request_timestamps:
        last_activity_time = max(sess.request_timestamps)
        idle_seconds = (now - last_activity_time).total_seconds()
        idle_minutes = idle_seconds / 60
        idle_str = f"{idle_minutes:.1f} minutes"
    else:
        idle_seconds = (now - sess.last_seen).total_seconds()
        idle_minutes = idle_seconds / 60
        idle_str = f"{idle_minutes:.1f} minutes"
    
    return duration_minutes, idle_str, session_status

def mark_session_ended(sess: SessionData) -> SessionData:
    """Mark a session as explicitly ended by setting the ended_at timestamp."""
    if not sess.ended_at:
        sess.ended_at = datetime.utcnow()
    return sess

# ------------------------------------------------------------
# Helper functions for loading and saving rules/policies
# ------------------------------------------------------------
def load_rules():
    """Load and compile rules from a YAML file."""
    try:
        with open(RULES_FILE, "r") as file:
            rules_data = yaml.safe_load(file)
        compiled_rules = {}
        if rules_data and "rules" in rules_data:
            for rule in rules_data["rules"]:
                if rule.get("enabled", True):
                    rule_dict = {
                        "type": rule["type"],
                        "subtype": rule.get("subtype", ""),  # Optional for security-pattern rules
                        "action": rule.get("action", "block"),
                        "severity": rule.get("severity", "medium"),
                        "description": rule.get("description", "")
                    }
                    # Add pattern for regex-based rules
                    if "pattern" in rule:
                        rule_dict["pattern"] = re.compile(rule["pattern"], re.IGNORECASE)
                    # Add header fields for header manipulation rules
                    if rule["type"] == "header-manipulation":
                        rule_dict["header_name"] = rule.get("header_name", "")
                        if rule["subtype"] in ["add-header", "replace-header"]:
                            rule_dict["header_value"] = rule.get("header_value", "")
                    # Add session-specific parameters
                    if rule["type"] == "session-management":
                        if "max_requests" in rule:
                            rule_dict["max_requests"] = rule["max_requests"]
                        if "max_blocked" in rule:
                            rule_dict["max_blocked"] = rule["max_blocked"]
                        if "block_duration" in rule:
                            rule_dict["block_duration"] = rule["block_duration"]
                        if "time_window" in rule:
                            rule_dict["time_window"] = rule["time_window"]
                    # Add IP-based header manipulation parameters
                    if rule["type"] == "header-manipulation" and "suspicious_ips" in rule:
                        rule_dict["suspicious_ips"] = rule["suspicious_ips"]
                    compiled_rules[rule["id"]] = rule_dict
        return compiled_rules
    except Exception as e:
        print(f"Error loading rules: {e}")
        return {}

def load_policies():
    """Load policies from a YAML file."""
    try:
        with open(POLICIES_FILE, "r") as file:
            policies_data = yaml.safe_load(file)
        active_policies = {}
        if policies_data and "policies" in policies_data:
            for policy in policies_data["policies"]:
                # Include all policies, not just enabled ones
                active_policies[policy["id"]] = {
                    "name": policy["name"],
                    "rules": policy["rules"],
                    "description": policy.get("description", ""),
                    "enabled": policy.get("enabled", True)
                }
        print(f"Loaded {len(active_policies)} policies from {POLICIES_FILE}")
        return active_policies
    except Exception as e:
        print(f"Error loading policies: {e}")
        return {}

def save_rules(rules_dict):
    """Save rules to YAML file."""
    rules_list = []
    for rule_id, rule_data in rules_dict.items():
        rule = {
            "id": rule_id,
            "type": rule_data.get("type"),
            "action": rule_data.get("action"),
            "severity": rule_data.get("severity"),
            "description": rule_data.get("description", ""),
            "enabled": rule_data.get("enabled", True)
        }
        # Only add subtype for header-manipulation and session-management rules
        if rule_data.get("type") in ["header-manipulation", "session-management"]:
            rule["subtype"] = rule_data.get("subtype", "")
        
        if "pattern" in rule_data:
            rule["pattern"] = rule_data.get("pattern").pattern if hasattr(rule_data.get("pattern"), "pattern") else rule_data.get("pattern")
        if rule_data.get("type") == "header-manipulation":
            if "header_name" in rule_data:
                rule["header_name"] = rule_data.get("header_name")
            if "header_value" in rule_data and rule_data.get("subtype") in ["add-header", "replace-header"]:
                rule["header_value"] = rule_data.get("header_value")
        # Add session-specific parameters
        if rule_data.get("type") == "session-management":
            if "max_requests" in rule_data:
                rule["max_requests"] = rule_data.get("max_requests")
            if "max_blocked" in rule_data:
                rule["max_blocked"] = rule_data.get("max_blocked")
            if "block_duration" in rule_data:
                rule["block_duration"] = rule_data.get("block_duration")
            if "time_window" in rule_data:
                rule["time_window"] = rule_data.get("time_window")
        # Add IP-based header manipulation parameters
        if rule_data.get("type") == "header-manipulation" and "suspicious_ips" in rule_data:
            rule["suspicious_ips"] = rule_data.get("suspicious_ips")
        rules_list.append(rule)
    rules_data = {"rules": rules_list}
    with open(RULES_FILE, "w") as file:
        yaml.dump(rules_data, file, default_flow_style=False)

def save_policies(policies_dict):
    """Save policies to YAML file."""
    policies_list = []
    for policy_id, policy_data in policies_dict.items():
        policy = {
            "id": policy_id,
            "name": policy_data.get("name"),
            "rules": policy_data.get("rules"),
            "description": policy_data.get("description", ""),
            "enabled": policy_data.get("enabled", True)
        }
        policies_list.append(policy)
    policies_data = {"policies": policies_list}
    with open(POLICIES_FILE, "w") as file:
        yaml.dump(policies_data, file, default_flow_style=False)

def prepare_request_for_model(request_dict, tokenizer, max_length=2000):
    """
    Takes a dictionary representing an HTTP request and returns a numpy array ready for model prediction.
    """
    # Remove query string from Uri
    uri = str(request_dict.get("Uri", ""))
    uri = uri.split("?")[0] if "?" in uri else uri
    # Remove spaces from Cookie and User-Agent only
    user_agent = str(request_dict.get("User-Agent", "")).replace(" ", "")
    cookie = str(request_dict.get("Cookie", "")).replace(" ", "")
    combined_text = " ".join([
        uri,
        user_agent,
        cookie,
        str(request_dict.get("Post-Query", "")),
        str(request_dict.get("Get-Query", "")),
    ])
    
    # Tokenize and pad
    seq = tokenizer.texts_to_sequences([combined_text])
    padded = pad_sequences(seq, maxlen=max_length)
    return padded

async def convert_request_to_dict(request: Request) -> dict:
    """Convert a FastAPI request to the format expected by the model."""
    # Extract basic request components
    method = request.method
    url = request.url.path

    # Extract headers with defaults if not provided
    cookie_header = request.headers.get("cookie", "")
    user_agent = request.headers.get("user-agent", "")
    content_length = request.headers.get("content-length", "0")
    content_type = request.headers.get("content-type", "text/html")

    # Build GET_Query from query parameters (e.g., ?key=value&...)
    get_query = "&".join(f"{key}={value}" for key, value in request.query_params.items())

    # For POST/PUT/PATCH methods, get the body as a string; otherwise, leave empty.
    if method.upper() in ["POST", "PUT", "PATCH"]:
        post_query = (await request.body()).decode("utf-8", "ignore")
    else:
        post_query = ""

    # Construct the dictionary in the required format
    request_dict = {
        "Uri": url,
        "User-Agent": user_agent,
        "Cookie": cookie_header,
        "Post-Query": post_query,
        "Get-Query": get_query,
    }

    return request_dict

async def make_ml_prediction(request: Request, model, tokenizer) -> str:
    """Make ML prediction for a request using the loaded model and tokenizer."""
    try:
        # Get the mapping of encoded labels to original class names
        class_index_to_name = {
            0: 'commandinjection', 1: 'ldapinjection', 2: 'pathtraversal',
            3: 'rce', 4: 'sqlinjection',
            5: 'ssi', 6: 'ssrf', 7: 'valid', 8: 'xpathinjection', 9: 'xss'
        }

        # Convert request to dictionary format
        request_dict = await convert_request_to_dict(request)
        
        # Prepare request for model
        preprocessed_input = prepare_request_for_model(request_dict, tokenizer)
        
        # Make prediction
        prediction = model.predict(preprocessed_input, verbose=0)
        
        # Extract the predicted class as a scalar
        predicted_class = int(np.argmax(prediction, axis=1)[0])
        predicted_class_name = class_index_to_name[predicted_class]
        
        print(f"ML Prediction -> {predicted_class_name}")
        return predicted_class_name
        
    except Exception as e:
        print(f"Error making ML prediction: {e}")
        return "valid"  # Default to valid if prediction fails

# ------------------------------------------------------------
# User Lookup: Get registered domains and their backend IPs
# ------------------------------------------------------------
async def get_all_users_backendips() -> dict[Any, Any]:
    """
    Fetch all user documents from the 'users' index and return a mapping of domain to backend_ip.
    Assumes each document has fields 'domain' and 'backend_ip'.
    """
    query = {
        "query": {"match_all": {}},
        "size": 1000
    }
    user_backend_map = {}
    user_prefix_map = {}
    try:
        es = app.state.esAuth
        response = await es.search(index="users", body=query)
        hits = response["hits"]["hits"]
        print(f"Fetched {len(hits)} users")
        for hit in hits:
            source = hit["_source"]
            domain = source.get("domain")
            prefix = source.get("prefix")
            backend_ip = source.get("backend_ip")
            if domain and backend_ip and prefix:
                user_backend_map[domain] = [backend_ip, prefix]
        return user_backend_map
    except ConnectionError as ce:
        print("Network/Connection error:", ce)
        return {}
    except TransportError as te:
        print("Transport error:", te)
        return {}
    except Exception as e:
        print("Other error:", e)
        return {}

# ------------------------------------------------------------
# Lifespan: Startup and shutdown tasks including background user updates
# ------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Set Elasticsearch endpoints from environment variables
    es_auth_url = os.getenv("ELASTICSEARCH_AUTH_URL", "http://localhost:9201")
    es_logs_url = os.getenv("ELASTICSEARCH_LOGS_URL", "http://localhost:9200")

    # Initialize Redis connection with error handling
    try:
        app.state.redis = await aioredis.from_url("redis://localhost:6379/0")
        app.state.redis_enabled = True
        print("Redis connection established successfully")
    except Exception as e:
        print(f"Warning: Redis connection failed: {e}")
        print("Session tracking will be disabled")
        app.state.redis = None
        app.state.redis_enabled = False

    # load Model
    try:
        app.state.model = load_model("cnn-lstm_character-level(98.9)(augmanted).h5")
        print("Model loaded successfully")
    except Exception as e:
        print(f"Warning: Model loading failed: {e}")
        print("ML-based detection will be disabled")
        app.state.model = None

    # load Tokenizer
    try:
        with open("token-150-2000(98.9)(augmanted).pkl", "rb") as f:
            app.state.tokenizer = pickle.load(f)
        print("Tokenizer loaded successfully")
    except Exception as e:
        print(f"Warning: Tokenizer loading failed: {e}")
        print("Tokenizer-based detection will be disabled")
        app.state.tokenizer = None

    # Model configuration constants
    app.state.text_features = ["Uri", "User-Agent", "Cookie", "Post-Query", "Get-Query"]
    app.state.max_chars = 150
    app.state.max_length = 2000

    app.state.esLogs = AsyncElasticsearch(hosts=[es_logs_url], verify_certs=False)
    app.state.esAuth = AsyncElasticsearch(hosts=[es_auth_url], verify_certs=False)
    app.state.compiled_rules = load_rules()
    app.state.active_policies = load_policies()

    # Load initial user domain mapping
    app.state.users = await get_all_users_backendips()

    # Initialize indices for all domains
    for domain in app.state.users.keys():
        await initialize_domain_indices(domain, app.state.esAuth)

    # Background task to update user mapping periodically
    async def update_users_periodically():
        while True:
            await asyncio.sleep(20)
            app.state.users = await get_all_users_backendips()

    task = asyncio.create_task(update_users_periodically())

    try:
        yield
    finally:
        if hasattr(app.state, 'esAuth'):
            await app.state.esAuth.close()
        if hasattr(app.state, 'esLogs'):
            await app.state.esLogs.close()
        if hasattr(app.state, 'redis') and app.state.redis:
            await app.state.redis.close()
        task.cancel()

app = FastAPI(lifespan=lifespan)

# ------------------------------------------------------------
# HTTPS Redirect Middleware (must be applied before reverse proxy)
# ------------------------------------------------------------
# @app.middleware("http")
# async def force_https_middleware(request: Request, call_next):
#     # Always force HTTPS - if no certificates exist, return error
#     if request.url.path.startswith("/api/") or request.url.path.startswith("/api/waf") or request.url.path.startswith("/api/certificates") or request.url.path.startswith("/health"):
#         return await call_next(request)

#     if request.url.scheme == "http":
#         # Check if certificates exist
#         if (
#             os.path.exists(SSL_CERT_FILE)
#             and os.path.exists(SSL_KEY_FILE)
#             and os.path.getsize(SSL_CERT_FILE) > 0
#             and os.path.getsize(SSL_KEY_FILE) > 0
#         ):
#             # Certificates exist - redirect to HTTPS
#             host = request.headers.get("host", "").split(":")[0]
#             https_url = f"https://{host}{request.url.path}"
#             if request.url.query:
#                 https_url += f"?{request.url.query}"
#             return Response(status_code=301, headers={"Location": https_url})
#         else:
#             # No certificates - return error
#             return JSONResponse(
#                 status_code=503,
#                 content={
#                     "error": "HTTPS required but no SSL certificates available",
#                     "message": "Please create SSL certificates first using the certificate API",
#                     "endpoint": "/api/certificates/create"
#                 }
#             )
#     return await call_next(request)

# ------------------------------------------------------------
# Unified Middleware: Combined Session Management and Reverse Proxy
# ------------------------------------------------------------
@app.middleware("http")
async def unified_middleware(request: Request, call_next):
    # Skip middleware logic for API endpoints
    # if request.url.path.startswith("/api") or request.url.path.startswith("/api/waf") or request.url.path.startswith("/health"):

    #     return await call_next(request)

    # Skip WAF logic for API endpoints
    if request.url.path.startswith("/api/") or request.url.path == "/health" or request.url.path.startswith("/api/waf"):
        return await call_next(request)

    # Extract the domain from the Host header (strip port if present)
    host_header = request.headers.get("host")
    if not host_header:
        return JSONResponse({"error": "No Host header provided"}, status_code=400)
    user_domain = host_header.split(":")[0]

    # Use the domain to look up the backend IP
    user_data = app.state.users.get(user_domain)
    if not user_data:
        return JSONResponse({"error": f"User not found for domain: {user_domain}"}, status_code=404)
    
    backend_ip = user_data[0]
    prefix = user_data[1]

    # Session management (only if Redis is available)
    session = None
    sid = None
    new_cookie = False
    
    if getattr(request.app.state, 'redis_enabled', False):
        redis = request.app.state.redis
        cookies = request.cookies or {}
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "")
        
        # Generate session fingerprint based on client characteristics
        session_fingerprint = generate_session_fingerprint(user_domain, client_ip, user_agent)
        
        # Try to get session ID from cookie first
        sid = cookies.get("WAF_SESSION_ID")
        
        # If no cookie or cookie doesn't match fingerprint, look for existing session with this fingerprint
        if not sid or not sid.startswith(session_fingerprint):
            # Look for existing session with this fingerprint
            existing_keys = await redis.keys(f"session:{user_domain}:{session_fingerprint}*")
            if existing_keys:
                # Use the existing session ID
                existing_key = existing_keys[0].decode()
                sid = existing_key.split(":")[2]
                print(f"Found existing session for fingerprint: {sid}")
                new_cookie = True  # Set cookie to reuse existing session
            else:
                # No existing session found - create new session ID with fingerprint
                sid = f"{session_fingerprint}-{uuid.uuid4().hex[:8]}"
                session = SessionData(
                    domain=user_domain,
                    user_agent=user_agent,
                    ip_address=client_ip
                )
                new_cookie = True

        try:
            # Check if session is blocked before processing
            block_key = f"block:{user_domain}:{sid}"
            is_blocked = await redis.get(block_key)
            if is_blocked:
                # Check if block duration has expired
                ttl = await redis.ttl(block_key)
                if ttl <= 0:
                    # Block has expired, remove both block and session data
                    await redis.delete(block_key)
                    await redis.delete(f"session:{user_domain}:{sid}")
                    # Look for existing session with this fingerprint or create new one
                    existing_keys = await redis.keys(f"session:{user_domain}:{session_fingerprint}*")
                    if existing_keys:
                        # Use the existing session ID
                        existing_key = existing_keys[0].decode()
                        sid = existing_key.split(":")[2]
                        print(f"Found existing session after block expiration: {sid}")
                    else:
                        # Create new session with reset counters
                        sid = f"{session_fingerprint}-{uuid.uuid4().hex[:8]}"
                        new_cookie = True
                        session = SessionData(
                            domain=user_domain,
                            user_agent=user_agent,
                            ip_address=client_ip
                        )
                        # New session always starts with clean counters
                        session.blocked_count = 0
                        session.blocked_requests = []
                        session.attack_patterns = {}
                        session.request_patterns = {}
                else:
                    return JSONResponse(
                        status_code=403,
                        content={"error": "Session temporarily blocked", "reason": "Rate limit or security threshold exceeded", "ttl": ttl},
                        headers={"X-WAF-Rule-ID": "session-block"}
                    )

            # Use domain-specific session key
            session_key = f"session:{user_domain}:{sid}"
            pickled = await redis.get(session_key)
            if pickled:
                # Check if session has expired
                ttl = await redis.ttl(session_key)
                if ttl <= 0:
                    # Session has expired, create new one
                    await redis.delete(session_key)
                    # Look for existing session with this fingerprint or create new one
                    existing_keys = await redis.keys(f"session:{user_domain}:{session_fingerprint}*")
                    if existing_keys:
                        # Use the existing session ID
                        existing_key = existing_keys[0].decode()
                        sid = existing_key.split(":")[2]
                        print(f"Found existing session after expiration: {sid}")
                        new_cookie = True  # Set cookie to reuse existing session
                    else:
                        session = SessionData(
                            domain=user_domain,
                            user_agent=user_agent,
                            ip_address=client_ip
                        )
                        new_cookie = True
                else:
                    session: SessionData = pickle.loads(pickled)
                    
                    # Verify session belongs to this client (additional security check)
                    if session.ip_address != client_ip or session.user_agent != user_agent:
                        print(f"Session fingerprint mismatch - creating new session")
                        await redis.delete(session_key)
                        session = SessionData(
                            domain=user_domain,
                            user_agent=user_agent,
                            ip_address=client_ip
                        )
                        new_cookie = True
                    else:
                        # Check if this session was previously blocked but block has expired
                        block_key = f"block:{user_domain}:{sid}"
                        is_blocked = await redis.get(block_key)
                        if is_blocked:
                            ttl = await redis.ttl(block_key)
                            if ttl <= 0:
                                # Block has expired, reset blocked count
                                print(f"Block expired for session {sid}, resetting blocked_count from {session.blocked_count} to 0")
                                session.blocked_count = 0
                                session.blocked_requests = []
                                session.attack_patterns = {}
                                # Remove the expired block
                                await redis.delete(block_key)
                        
                        # Clean up old timestamps immediately when loading session
                        current_time = datetime.utcnow()
                        session.request_timestamps = [ts for ts in session.request_timestamps if (current_time - ts).total_seconds() <= 60]
                        print(f"Loaded session with {len(session.request_timestamps)} recent timestamps, blocked_count={session.blocked_count}")
            else:
                # No existing session found - create new one
                session = SessionData(
                    domain=user_domain,
                    user_agent=user_agent,
                    ip_address=client_ip
                )
                new_cookie = True

            # Update session
            session.request_count += 1
            # Don't update last_seen here - update it after WAF check
            
            # Clean up old timestamps (older than the maximum time window used by any rule) to prevent memory bloat
            # Use a reasonable default of 300 seconds (5 minutes) to cover most use cases
            cleanup_window = 300  # seconds
            current_time = datetime.utcnow()
            session.request_timestamps = [ts for ts in session.request_timestamps if (current_time - ts).total_seconds() <= cleanup_window]

            # Track request pattern
            endpoint = request.url.path
            session.request_patterns[endpoint] = session.request_patterns.get(endpoint, 0) + 1

        except Exception as e:
            print(f"Warning: Session tracking error: {e}")
            # Continue without session if Redis fails

    # Prepare request details for proxy
    method = request.method
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    query_params = dict(request.query_params)
    body = await request.body()
    body_content = body.decode("utf-8", "ignore") if body else ""

    # Run unified WAF logic (ONCE per request with session data if available)
    is_blocked, rule_id, action, modified_headers = await unified_waf_logic(request, headers, session=session, body_content=body_content)
    
    # Make ML prediction (only if model and tokenizer are available)
    if hasattr(app.state, 'model') and app.state.model is not None and hasattr(app.state, 'tokenizer') and app.state.tokenizer is not None:
        ml_prediction = await make_ml_prediction(request, app.state.model, app.state.tokenizer)
        if ml_prediction != "valid":
            # Block and log the request like rule-based blocking
            print(f"ML prediction blocked: {ml_prediction}")
            await log_request(request, log_index=f"{user_domain}_log", status=f"BLOCKED-ML-{ml_prediction}", modified_headers=modified_headers)
            
            # Handle session updates for ML blocked requests
            if session and getattr(request.app.state, 'redis_enabled', False):
                # Increment blocked count for ML blocked requests
                session.blocked_count += 1
                blocked_info = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'url': str(request.url),
                    'method': request.method,
                    'rule_id': f"ML-{ml_prediction}"
                }
                session.blocked_requests.append(blocked_info)
                session.blocked_requests = session.blocked_requests[-10:]  # Keep only last 10 blocked requests
                
                # Update session data without creating a block (ML predictions are treated like attack rules)
                print(f"ML attack detected: {ml_prediction} - updated blocked_count to {session.blocked_count}")
                session_key = f"session:{user_domain}:{sid}"
                await redis.set(session_key, pickle.dumps(session), ex=SESSION_TTL)
            
            return JSONResponse({"error": "Request blocked by WAF", "rule_id": f"ML-{ml_prediction}"}, status_code=403)
    
    # Preserve original values BEFORE any modifications
    original_rule_id = rule_id  # Preserve for logging
    original_action = action    # Preserve for logging
    
    

    if action == "alert":
        print(f"Alert detected: Rule {rule_id}")
        # Continue processing the request normally (don't block)
        # Don't reset rule_id - keep it for logging

    if is_blocked:
        print(f"Malicious request detected: Rule {rule_id}")
        await log_request(request, log_index=f"{user_domain}_log", status=f"BLOCKED-{rule_id}", modified_headers=modified_headers)
        
        # Handle session updates for ALL blocked requests
        if session and getattr(request.app.state, 'redis_enabled', False):
            # Increment blocked count for ALL blocked requests (both attack and session rules)
            session.blocked_count += 1
            blocked_info = {
                'timestamp': datetime.utcnow().isoformat(),
                'url': str(request.url),
                'method': request.method,
                'rule_id': rule_id
            }
            session.blocked_requests.append(blocked_info)
            session.blocked_requests = session.blocked_requests[-10:]  # Keep only last 10 blocked requests
            
            # Get the rule to determine if it's session-based
            rules = await get_domain_rules(user_domain, request.app.state.esAuth)
            rule = rules.get(rule_id, {})
            
            # Only create session blocks for session-based rules
            if rule.get("type") == "session-management":
                # Use the rule's configured block duration
                block_duration = rule.get("block_duration", 300)
                print(f"Session-based rule triggered: blocking session for {block_duration} seconds")
                
                # Create a temporary block record in Redis
                block_key = f"block:{user_domain}:{sid}"
                await redis.set(block_key, "blocked", ex=block_duration)
                
                # Update session data
                session_key = f"session:{user_domain}:{sid}"
                await redis.set(session_key, pickle.dumps(session), ex=block_duration)
            else:
                # For non-session rules (SQL injection, XSS, etc.), just update session data without blocking
                print(f"Attack rule triggered: {rule_id} (type: {rule.get('type', 'unknown')}) - updated blocked_count to {session.blocked_count}")
                # Update session data without creating a block
                session_key = f"session:{user_domain}:{sid}"
                await redis.set(session_key, pickle.dumps(session), ex=SESSION_TTL)
        
        return JSONResponse({"error": "Request blocked by WAF", "rule_id": rule_id}, status_code=403)
    
    headers = modified_headers

    # Attach session to request.state for potential use by other parts of the application
    if session:
        request.state.session = session
        request.state.session_id = sid

    # Construct the backend URL
    backend_url = f"{backend_ip}{prefix}"
    async with AsyncClient(base_url=backend_url) as request_client:
        try:
            backend_response = await request_client.request(
                method,
                request.url.path,  # Use the entire incoming path for forwarding
                headers=headers,
                params=query_params,
                content=body if method not in ("GET", "HEAD") else None,
                follow_redirects=False
            )

            # Process and adjust response headers
            response_headers = dict(backend_response.headers)
            if "location" in response_headers:
                location = urlparse(response_headers["location"])
                location = urlunparse(("", "", location.path, location.params, location.query, location.fragment))
                response_headers["location"] = location.replace(f"{prefix}", "", 1)
            response_headers.pop("transfer-encoding", None)
            response_headers.pop("content-encoding", None)
            response_headers.pop("content-length", None)

            # Determine the final status for logging
            final_status = "ALLOWED"
            if original_action == "alert":
                final_status = f"ALERT-{original_rule_id}"
            
            # Single logging point for all cases
            await log_request(request, log_index=f"{user_domain}_log", response=backend_response, status=final_status, modified_headers=modified_headers)
            
            response = Response(
                content=backend_response.content,
                status_code=backend_response.status_code,
                headers=response_headers
            )

            # Handle session updates after successful response
            if session and getattr(request.app.state, 'redis_enabled', False):
                # Update last_seen after WAF logic (so idle time calculation works correctly)
                session.last_seen = datetime.utcnow()
                
                # Add timestamp for successful requests (for rate limiting)
                session.request_timestamps.append(datetime.utcnow())
                
                # Write back to Redis with domain-specific key
                await redis.set(f"session:{user_domain}:{sid}", pickle.dumps(session), ex=SESSION_TTL)

                if new_cookie:
                    response.set_cookie("WAF_SESSION_ID", sid, httponly=True, max_age=SESSION_TTL)
            
            return response
            
        except Exception as e:
            print(f"Proxy error: {e}")
            await log_request(request, log_index=f"{user_domain}_log", status=f"ERROR-{str(e)}", modified_headers=modified_headers)
            return JSONResponse({"error": str(e)}, status_code=500)

# ------------------------------------------------------------
# Unified WAF Logic: Check incoming requests against all active rules and policies
# ------------------------------------------------------------

async def unified_waf_logic(request: Request, headers: Dict[str, str], session: Optional[SessionData] = None, body_content: str = "") -> tuple:
    """
    Unified WAF logic that checks against all active rules and policies with conflict resolution.
    Returns: (is_blocked: bool, rule_id: str, action: str, modified_headers: Dict[str, str])
    """
    # Get domain from host header
    host_header = request.headers.get("host")
    if not host_header:
        return False, "", "", headers
    domain = host_header.split(":")[0]
    
    # Get domain-specific rules and policies (ONCE per request)
    es = request.app.state.esAuth
    rules = await get_domain_rules(domain, es)
    policies = await get_domain_policies(domain, es)
    
    print(f"DEBUG: Domain {domain} - Loaded {len(rules)} rules and {len(policies)} policies")
    print(f"DEBUG: Available rules: {list(rules.keys())}")
    print(f"DEBUG: Available policies: {list(policies.keys())}")
    
    # Build the set of active rule IDs from enabled policies
    active_rule_ids = set()
    for policy in policies.values():
        if policy.get("enabled", True):
            active_rule_ids.update(policy["rules"])
    
    print(f"DEBUG: Active rule IDs: {active_rule_ids}")

    modified_headers = headers.copy()
    matching_rules = []  # Collect all matching rules for conflict resolution

    # First pass: Header manipulation rules (always applied, no conflicts)
    for rule_id in active_rule_ids:
        if rule_id not in rules:
            continue
        rule = rules[rule_id]
        if rule["type"] == "header-manipulation" and rule.get("action") == "modify":
            print(f"DEBUG: Processing header manipulation rule: {rule_id}")
            if "header_name" in rule and "header_value" in rule:
                if rule["subtype"] == "add-header":
                    # Check if this is an IP-based header rule
                    if "suspicious_ips" in rule and rule["suspicious_ips"]:
                        client_ip = request.client.host
                        print(f"DEBUG: Checking suspicious IP rule {rule_id} for IP {client_ip}")
                        print(f"DEBUG: Suspicious IPs: {rule['suspicious_ips']}")
                        if client_ip in rule["suspicious_ips"]:
                            modified_headers[rule["header_name"]] = rule["header_value"]
                            print(f"Added header {rule['header_name']} with value {rule['header_value']} for suspicious IP {client_ip}")
                        else:
                            print(f"DEBUG: IP {client_ip} not in suspicious IPs list")
                    else:
                        # Regular header addition
                        modified_headers[rule["header_name"]] = rule["header_value"]
                        print(f"Added header {rule['header_name']} with value {rule['header_value']}")
                elif rule["subtype"] == "replace-header":
                    modified_headers[rule["header_name"]] = rule["header_value"]
                    print(f"Replaced header {rule['header_name']} with value {rule['header_value']}")
            elif rule["subtype"] == "delete-header" and "header_name" in rule:
                modified_headers.pop(rule["header_name"].lower(), None)
                print(f"Deleted header {rule['header_name']}")

    print(f"DEBUG: Modified headers after header manipulation: {modified_headers}")

    # Second pass: Session-based rules (only if session data is provided)
    if session:
        for rule_id in active_rule_ids:
            if rule_id not in rules:
                continue
            rule = rules[rule_id]
            
            if rule["type"] == "session-management":
                if rule["subtype"] == "session-rate":
                    # Rolling window rate limiting with configurable time window
                    max_requests = rule.get("max_requests", 100)
                    time_window = rule.get("time_window", 60)  # Default to 60 seconds if not specified
                    current_time = datetime.utcnow()
                    
                    # Count requests from the last time_window seconds only
                    requests_in_window = 0
                    recent_timestamps = []
                    for timestamp in session.request_timestamps:
                        time_diff = (current_time - timestamp).total_seconds()
                        if time_diff <= time_window:
                            requests_in_window += 1
                            recent_timestamps.append(timestamp)
                    
                    print(f"Rate limit check: requests_in_window={requests_in_window}, max_requests={max_requests}, time_window={time_window}s")
                    print(f"Recent timestamps: {[ts.strftime('%H:%M:%S') for ts in recent_timestamps]}")
                    
                    # Block if requests in last time_window seconds exceeds the limit
                    if requests_in_window > max_requests:
                        print(f"Session-rate rule triggered: requests_in_window={requests_in_window}, max_requests={max_requests}, time_window={time_window}s")
                        matching_rules.append(RuleMatch(rule_id, rule, get_rule_priority(rule)))
                
                elif rule["subtype"] == "session-blocked":
                    # Check if session has too many blocked requests
                    max_blocked = rule.get("max_blocked", 5)
                    print(f"Session-blocked check: blocked_count={session.blocked_count}, max_blocked={max_blocked}")
                    if session.blocked_count >= max_blocked:
                        print(f"Session-blocked rule triggered: blocked_count={session.blocked_count}, max_blocked={max_blocked}")
                        matching_rules.append(RuleMatch(rule_id, rule, get_rule_priority(rule)))

    # Third pass: Pattern-based rules
    url = unquote(str(request.url))
    # Use modified_headers instead of request.headers to catch headers added by header manipulation rules
    headers_lower = {k.lower(): v for k, v in modified_headers.items()}
    cookies = request.cookies
    query_params = {key: unquote(value) for key, value in request.query_params.items()}
    
    # Use body content passed from middleware instead of reading request body again
    body = body_content

    for rule_id in active_rule_ids:
        if rule_id not in rules:
            continue
        rule = rules[rule_id]
        if rule["type"] == "header-manipulation":
            continue
        if rule.get("action") not in ["block", "alert"]:
            continue
        if "pattern" not in rule:
            continue
        pattern = rule["pattern"]
        
        print(f"DEBUG: Checking pattern rule {rule_id} with pattern '{pattern.pattern}'")
        print(f"DEBUG: Available headers for pattern matching: {list(headers_lower.keys())}")
        
        # Check if pattern matches in any part of the request
        pattern_matched = False
        if pattern.search(url):
            pattern_matched = True
        for param_value in query_params.values():
            if pattern.search(param_value):
                pattern_matched = True
        # Check header names and values
        for header_name, header_value in headers_lower.items():
            if pattern.search(header_name) or pattern.search(header_value):
                print(f"DEBUG: Pattern '{pattern.pattern}' matched header '{header_name}' = '{header_value}'")
                pattern_matched = True
        for cookie_value in cookies.values():
            if pattern.search(cookie_value):
                pattern_matched = True
        if body and pattern.search(body):
            pattern_matched = True
            
        if pattern_matched:
            print(f"Pattern rule {rule_id} matched! Pattern: {pattern.pattern}, Action: {rule.get('action')}")
            matching_rules.append(RuleMatch(rule_id, rule, get_rule_priority(rule)))
        else:
            print(f"DEBUG: Pattern rule {rule_id} did not match")

    # Conflict resolution: Sort by priority and determine final action
    if matching_rules:
        # Sort by priority (highest first)
        matching_rules.sort()
        highest_priority_rule = matching_rules[0]
        
        print(f"Conflict resolution: {len(matching_rules)} matching rules")
        for rule_match in matching_rules:
            print(f"  - {rule_match.rule_id}: {rule_match.rule.get('action')} (severity: {rule_match.rule.get('severity')}, priority: {rule_match.priority})")
        
        action = highest_priority_rule.rule.get("action", "block")
        rule_id = highest_priority_rule.rule_id
        
        if action == "block":
            print(f"Final decision: BLOCK by rule {rule_id} (priority: {highest_priority_rule.priority})")
            return True, rule_id, action, modified_headers
        elif action == "alert":
            print(f"Final decision: ALERT by rule {rule_id} (priority: {highest_priority_rule.priority})")
            return False, rule_id, action, modified_headers
        else:
            print(f"Final decision: ALLOW by rule {rule_id} (priority: {highest_priority_rule.priority})")
            return False, rule_id, action, modified_headers

    return False, "", "", modified_headers

# ------------------------------------------------------------
# Logging: Log requests and responses to Elasticsearch
# ------------------------------------------------------------
async def log_request(request: Request, log_index: str, response: Response=None, status: str = "ALLOWED", modified_headers: Dict[str, str] = None):
    es = request.app.state.esLogs
    if es is None:
        print("Elasticsearch client is not initialized!")
        return

    try:
        body_content = (await request.body()).decode("utf-8", "replace")
    except Exception:
        body_content = "[Error reading body]"

    count_response = await es.count(index=log_index)
    index_size = count_response["count"]
    log_id = index_size + 1 if index_size else 1
    print(f"Logging entry {log_id} (index size: {index_size})")
    
    # Use modified headers if provided, otherwise use original headers
    headers_to_log = modified_headers if modified_headers is not None else dict(request.headers)
    
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "client_ip": request.client.host,
        "method": request.method,
        "url": str(request.url),
        "status": status,
        "user_agent": request.headers.get("user-agent", ""),
        "headers": headers_to_log,
        "type": "request",
        "query_params": dict(request.query_params),
        "body": body_content
    }
    
    # Add 'seen' field for block, alert, and error actions
    if status.startswith("BLOCKED") or status.startswith("ALERT") or status.startswith("ERROR"):
        log_entry["seen"] = "false"
        # Add severity for block and alert actions
        severity = None
        if status.startswith("BLOCKED-ML-"):
            # ML-blocked: assign severity based on class
            ml_class = status.replace("BLOCKED-ML-", "").lower()
            if ml_class in ["rce", "sqlinjection", "commandinjection"]:
                severity = "critical"
            elif ml_class in ["xss", "ssrf", "pathtraversal"]:
                severity = "high"
            elif ml_class in ["ldapinjection", "xpathinjection", "ssi"]:
                severity = "medium"
            else:
                severity = "low"
        elif status.startswith("BLOCKED-") or status.startswith("ALERT-"):
            # Try to extract rule_id from status (BLOCKED-<rule_id> or ALERT-<rule_id>)
            rule_id = status.split("-", 1)[-1]
            # Try to get the rule's severity from the rules index
            domain = request.headers.get("host", "").split(":")[0]
            es = request.app.state.esAuth
            try:
                rules = await get_domain_rules(domain, es)
                rule = rules.get(rule_id, {})
                severity = rule.get("severity", None)
            except Exception:
                severity = None
        if severity:
            log_entry["severity"] = severity
    
    try:
        await es.index(index=log_index, document=log_entry, id=str(log_id))
        # Log response for all non-blocked requests (ALLOWED, ALERT, etc.)
        if not status.startswith("BLOCKED") and response is not None:
            await log_response(request, log_index, response, log_id, status)
    except Exception as e:
        print(f"Error logging to Elasticsearch: {e}")

async def log_response(request: Request, log_index: str, response: Response, req_id: int, status: str = "ALLOWED"):
    es = request.app.state.esLogs
    if es is None:
        print("Elasticsearch client is not initialized!")
        return
    try:
        body_content = (await response.body()).decode("utf-8", "replace")
    except Exception:
        body_content = "[Error reading body]"
    log_entry = {
        "request_id": req_id,
        "timestamp": datetime.now().isoformat(),
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "type": "response",
        "body": body_content
    }
    try:
        await es.index(index=log_index, document=log_entry, id=str(req_id+1))
    except Exception as e:
        print(f"Error logging response to Elasticsearch: {e}")

# ------------------------------------------------------------
# API Endpoints for Rule and Policy Management
# ------------------------------------------------------------
# @app.get("/api/waf/rules", response_model=List[Dict[str, Any]])
# async def get_rules(request: Request):
#     # Reload rules from file
#     request.app.state.compiled_rules = load_rules()
#     compiled_rules = request.app.state.compiled_rules
#     rules_list = []
#     for rule_id, rule in compiled_rules.items():
#         rule_dict = {
#             "id": rule_id,
#             "type": rule["type"],
#             "action": rule["action"],
#             "severity": rule["severity"],
#             "description": rule.get("description", "")
#         }
#         # Only include subtype for header-manipulation and session-management rules
#         if rule["type"] in ["header-manipulation", "session-management"]:
#             rule_dict["subtype"] = rule.get("subtype", "")
        
#         if "pattern" in rule:
#             rule_dict["pattern"] = rule["pattern"].pattern if hasattr(rule["pattern"], "pattern") else rule["pattern"]
#         if rule["type"] == "header-manipulation":
#             if "header_name" in rule:
#                 rule_dict["header_name"] = rule["header_name"]
#             if "header_value" in rule and rule.get("subtype") in ["add-header", "replace-header"]:
#                 rule_dict["header_value"] = rule["header_value"]
#         rules_list.append(rule_dict)
#     return rules_list

# @app.post("/api/waf/rules", status_code=201)
# async def create_rule(rule: Rule, request: Request):
#     compiled_rules = request.app.state.compiled_rules
#     if rule.id in compiled_rules:
#         raise HTTPException(status_code=400, detail="Rule ID already exists")
#     try:
#         rule_dict = {
#             "id": rule.id,
#             "type": rule.type,
#             "action": rule.action,
#             "severity": rule.severity,
#             "description": rule.description,
#             "enabled": rule.enabled
#         }
#         # Only add subtype for header-manipulation and session-management rules
#         if rule.type in [RuleType.HEADER_MANIPULATION, RuleType.SESSION_MANAGEMENT]:
#             rule_dict["subtype"] = rule.subtype
        
#         if rule.pattern:
#             rule_dict["pattern"] = rule.pattern
#         if rule.type == RuleType.HEADER_MANIPULATION:
#             if not rule.header_name:
#                 raise HTTPException(status_code=400, detail="Header name is required for header manipulation rules")
#             rule_dict["header_name"] = rule.header_name
#             if rule.subtype in ["add-header", "replace-header"]:
#                 if not rule.header_value:
#                     raise HTTPException(status_code=400, detail="Header value is required for add-header and replace-header rules")
#                 rule_dict["header_value"] = rule.header_value
#         # Add session-specific parameters
#         if rule.type == RuleType.SESSION_MANAGEMENT:
#             if rule.max_requests is not None:
#                 rule_dict["max_requests"] = rule.max_requests
#             if rule.max_blocked is not None:
#                 rule_dict["max_blocked"] = rule.max_blocked
#             if rule.block_duration is not None:
#                 rule_dict["block_duration"] = rule.block_duration
#         # Add IP-based header manipulation parameters
#         if rule.type == RuleType.HEADER_MANIPULATION and rule.suspicious_ips is not None:
#             rule_dict["suspicious_ips"] = rule.suspicious_ips
#         compiled_rules[rule.id] = rule_dict
#         save_rules(compiled_rules)
#         return {"message": "Rule created successfully", "id": rule.id}
#     except Exception as e:
#         raise HTTPException(status_code=400, detail=f"Invalid rule: {str(e)}")

# @app.put("/api/waf/rules/{rule_id}")
# async def update_rule(rule_id: str, rule_update: RuleUpdate, request: Request):
#     compiled_rules = request.app.state.compiled_rules
#     if rule_id not in compiled_rules:
#         raise HTTPException(status_code=404, detail="Rule not found")
#     current_rule = compiled_rules[rule_id]
#     if rule_update.type is not None:
#         current_rule["type"] = rule_update.type
#     if rule_update.subtype is not None:
#         # Only update subtype for header-manipulation and session-management rules
#         if rule_update.type in [RuleType.HEADER_MANIPULATION, RuleType.SESSION_MANIPULATION] or current_rule["type"] in ["header-manipulation", "session-management"]:
#             current_rule["subtype"] = rule_update.subtype
#         else:
#             # Remove subtype for security-pattern rules
#             current_rule.pop("subtype", None)
#     if rule_update.pattern is not None:
#         try:
#             current_rule["pattern"] = re.compile(rule_update.pattern, re.IGNORECASE)
#         except Exception as e:
#             raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {str(e)}")
#     if rule_update.action is not None:
#         current_rule["action"] = rule_update.action
#     if rule_update.severity is not None:
#         current_rule["severity"] = rule_update.severity
#     if rule_update.description is not None:
#         current_rule["description"] = rule_update.description
#     if rule_update.enabled is not None:
#         current_rule["enabled"] = rule_update.enabled
#     if rule_update.header_name is not None:
#         current_rule["header_name"] = rule_update.header_name
#     if rule_update.header_value is not None:
#         current_rule["header_value"] = rule_update.header_value
#     # Add session-specific parameters
#     if rule_update.type == RuleType.SESSION_MANAGEMENT:
#         if rule_update.max_requests is not None:
#             current_rule["max_requests"] = rule_update.max_requests
#         if rule_update.max_blocked is not None:
#             current_rule["max_blocked"] = rule_update.max_blocked
#         if rule_update.block_duration is not None:
#             current_rule["block_duration"] = rule_update.block_duration
#     # Add IP-based header manipulation parameters
#     if rule_update.suspicious_ips is not None:
#         current_rule["suspicious_ips"] = rule_update.suspicious_ips
#     save_rules(compiled_rules)
#     return {"message": "Rule updated successfully"}

# @app.delete("/api/waf/rules/{rule_id}")
# async def delete_rule(rule_id: str, request: Request):
#     compiled_rules = request.app.state.compiled_rules
#     active_policies = request.app.state.active_policies
#     if rule_id not in compiled_rules:
#         raise HTTPException(status_code=404, detail="Rule not found")
#     del compiled_rules[rule_id]
#     save_rules(compiled_rules)
#     for policy in active_policies.values():
#         if rule_id in policy["rules"]:
#             policy["rules"].remove(rule_id)
#     save_policies(active_policies)
#     return {"message": "Rule deleted successfully"}

# @app.get("/api/waf/policies", response_model=List[Dict[str, Any]])
# async def get_policies(request: Request):
#     # Force reload policies from file
#     policies_data = load_policies()
#     request.app.state.active_policies = policies_data
    
#     policies_list = []
#     for policy_id, policy in policies_data.items():
#         policy_dict = {
#             "id": policy_id,
#             "name": policy["name"],
#             "rules": policy["rules"],
#             "description": policy.get("description", ""),
#             "enabled": policy.get("enabled", True)
#         }
#         policies_list.append(policy_dict)
#     return policies_list

# @app.post("/api/waf/policies", status_code=201)
# async def create_policy(policy: Policy, request: Request):
#     active_policies = request.app.state.active_policies
#     compiled_rules = request.app.state.compiled_rules
#     if policy.id in active_policies:
#         raise HTTPException(status_code=400, detail="Policy ID already exists")
#     for rule_id in policy.rules:
#         if rule_id not in compiled_rules:
#             raise HTTPException(status_code=400, detail=f"Rule {rule_id} does not exist")
#     active_policies[policy.id] = {
#         "name": policy.name,
#         "rules": policy.rules,
#         "description": policy.description,
#         "enabled": policy.enabled
#     }
#     save_policies(active_policies)
#     return {"message": "Policy created successfully", "id": policy.id}

# @app.put("/api/waf/policies/{policy_id}")
# async def update_policy(policy_id: str, policy_update: PolicyUpdate, request: Request):
#     active_policies = request.app.state.active_policies
#     compiled_rules = request.app.state.compiled_rules
#     if policy_id not in active_policies:
#         raise HTTPException(status_code=404, detail="Policy not found")
    
#     current_policy = active_policies[policy_id]
    
#     # Update fields only if provided
#     if policy_update.name is not None:
#         current_policy["name"] = policy_update.name
#     if policy_update.description is not None:
#         current_policy["description"] = policy_update.description
#     if policy_update.enabled is not None:
#         current_policy["enabled"] = policy_update.enabled
#     if policy_update.rules is not None:
#         # Verify all rules exist before updating
#         for rule_id in policy_update.rules:
#             if rule_id not in compiled_rules:
#                 raise HTTPException(status_code=400, detail=f"Rule {rule_id} does not exist")
#         current_policy["rules"] = policy_update.rules
    
#     save_policies(active_policies)
#     return {"message": "Policy updated successfully"}

# @app.delete("/api/waf/policies/{policy_id}")
# async def delete_policy(policy_id: str, request: Request):
#     active_policies = request.app.state.active_policies
#     if policy_id not in active_policies:
#         raise HTTPException(status_code=404, detail="Policy not found")
#     del active_policies[policy_id]
#     save_policies(active_policies)
#     return {"message": "Policy deleted successfully"}

# @app.get("/api/waf/statistics")
# async def get_statistics(request: Request):
#     es = request.app.state.esAuth  # Adjust index/client as needed
#     try:
#         total_requests = await es.count(index="waf-logs", body={"query": {"term": {"type": "request"}}})
#         blocked_requests = await es.count(index="waf-logs", body={"query": {"wildcard": {"status": "BLOCKED-*"}}})
#         top_rules_query = {
#             "size": 0,
#             "query": {"wildcard": {"status": "BLOCKED-*"}},
#             "aggs": {
#                 "top_rules": {
#                     "terms": {"field": "status.keyword", "size": 10}
#                 }
#             }
#         }
#         top_rules = await es.search(index="waf-logs", body=top_rules_query)
#         return {
#             "total_requests": total_requests["count"],
#             "blocked_requests": blocked_requests["count"],
#             "top_rules": [
#                 {"rule": bucket["key"], "count": bucket["doc_count"]}
#                 for bucket in top_rules["aggregations"]["top_rules"]["buckets"]
#             ] if "aggregations" in top_rules else []
#         }
#     except Exception as e:
#         print(f"Error getting statistics: {e}")
#         return {"error": str(e)}

async def initialize_domain_indices(domain: str, es: AsyncElasticsearch):
    """Initialize domain-specific rules and policies indices with default values."""
    try:
        # Create domain-specific indices
        rules_index = f"{domain}_rules"
        policies_index = f"{domain}_policies"

        # Check if indices exist
        rules_exists = await es.indices.exists(index=rules_index)
        policies_exists = await es.indices.exists(index=policies_index)

        # Load default rules and policies
        default_rules = load_rules()
        default_policies = load_policies()

        # Initialize rules index if it doesn't exist
        if not rules_exists:
            for rule_id, rule in default_rules.items():
                rule_doc = {
                    "id": rule_id,
                    "type": rule["type"],
                    "action": rule["action"],
                    "severity": rule["severity"],
                    "description": rule.get("description", ""),
                    "enabled": rule.get("enabled", True)
                }
                # Only add subtype for header-manipulation and session-management rules
                if rule["type"] in ["header-manipulation", "session-management"]:
                    rule_doc["subtype"] = rule.get("subtype", "")
                
                if "pattern" in rule:
                    rule_doc["pattern"] = rule["pattern"].pattern if hasattr(rule["pattern"], "pattern") else rule["pattern"]
                if rule["type"] == "header-manipulation":
                    if "header_name" in rule:
                        rule_doc["header_name"] = rule["header_name"]
                    if "header_value" in rule and rule.get("subtype") in ["add-header", "replace-header"]:
                        rule_doc["header_value"] = rule["header_value"]
                # Add session-specific parameters
                if rule["type"] == "session-management":
                    if "max_requests" in rule:
                        rule_doc["max_requests"] = rule["max_requests"]
                    if "max_blocked" in rule:
                        rule_doc["max_blocked"] = rule["max_blocked"]
                    if "block_duration" in rule:
                        rule_doc["block_duration"] = rule["block_duration"]
                    if "time_window" in rule:
                        rule_doc["time_window"] = rule["time_window"]
                # Add IP-based header manipulation parameters
                if rule["type"] == "header-manipulation" and "suspicious_ips" in rule:
                    rule_doc["suspicious_ips"] = rule["suspicious_ips"]
                
                await es.index(index=rules_index, document=rule_doc, id=rule_id)

        # Initialize policies index if it doesn't exist
        if not policies_exists:
            for policy_id, policy in default_policies.items():
                policy_doc = {
                    "id": policy_id,
                    "name": policy["name"],
                    "rules": policy["rules"],
                    "description": policy.get("description", ""),
                    "enabled": policy.get("enabled", True)
                }
                await es.index(index=policies_index, document=policy_doc, id=policy_id)

        return True
    except Exception as e:
        print(f"Error initializing indices for domain {domain}: {e}")
        return False

async def get_domain_rules(domain: str, es: AsyncElasticsearch) -> dict:
    """Get rules for a specific domain from Elasticsearch."""
    try:
        rules_index = f"{domain}_rules"
        print(f"Searching for rules in index: {rules_index}")
        
        # First check if index exists
        if not await es.indices.exists(index=rules_index):
            print(f"Index {rules_index} does not exist, initializing with default rules")
            await initialize_domain_indices(domain, es)
        
        # Get all rules
        response = await es.search(
            index=rules_index,
            body={
                "query": {"match_all": {}},
                "size": 1000  # Increase size to ensure we get all rules
            }
        )
        
        rules = {}
        for hit in response["hits"]["hits"]:
            rule = hit["_source"]
            rule_id = rule["id"]
            print(f"Found rule: {rule_id}")
            
            # Only include subtype for header-manipulation and session-management rules
            if rule["type"] not in ["header-manipulation", "session-management"]:
                rule.pop("subtype", None)  # Remove subtype for security-pattern rules
            
            if "pattern" in rule:
                rule["pattern"] = re.compile(rule["pattern"], re.IGNORECASE)
            rules[rule_id] = rule
            
        print(f"Total rules found: {len(rules)}")
        print(f"Rule IDs: {list(rules.keys())}")
        return rules
    except Exception as e:
        print(f"Error getting rules for domain {domain}: {e}")
        return {}

async def get_domain_policies(domain: str, es: AsyncElasticsearch) -> dict:
    """Get policies for a specific domain from Elasticsearch."""
    try:
        policies_index = f"{domain}_policies"
        response = await es.search(index=policies_index, body={"query": {"match_all": {}}})
        policies = {}
        for hit in response["hits"]["hits"]:
            policy = hit["_source"]
            policy_id = policy["id"]
            policies[policy_id] = policy
        return policies
    except Exception as e:
        print(f"Error getting policies for domain {domain}: {e}")
        return {}
    
#ehab################################################################################################################


#ehab################################################################################################################

# Domain-specific Rule Management
@app.get("/api/waf/{domain}/rules", response_model=List[Dict[str, Any]])
async def get_domain_rules_endpoint(domain: str, request: Request):
    rules = await get_domain_rules(domain, request.app.state.esAuth)
    return list(rules.values())

@app.post("/api/waf/{domain}/rules", status_code=201)
async def create_domain_rule(domain: str, rule: Rule, request: Request):
    rules_index = f"{domain}_rules"
    es = request.app.state.esAuth
    
    # Check if rule exists
    try:
        exists = await es.exists(index=rules_index, id=rule.id)
        if exists:
            raise HTTPException(status_code=400, detail="Rule ID already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    try:
        rule_dict = {
            "id": rule.id,
            "type": rule.type,
            "action": rule.action,
            "severity": rule.severity,
            "description": rule.description,
            "enabled": rule.enabled
        }
        # Only add subtype for header-manipulation and session-management rules
        if rule.type in [RuleType.HEADER_MANIPULATION, RuleType.SESSION_MANAGEMENT]:
            rule_dict["subtype"] = rule.subtype
        
        if rule.pattern:
            rule_dict["pattern"] = rule.pattern
        if rule.type == RuleType.HEADER_MANIPULATION:
            if not rule.header_name:
                raise HTTPException(status_code=400, detail="Header name is required for header manipulation rules")
            rule_dict["header_name"] = rule.header_name
            if rule.subtype in ["add-header", "replace-header"]:
                if not rule.header_value:
                    raise HTTPException(status_code=400, detail="Header value is required for add-header and replace-header rules")
                rule_dict["header_value"] = rule.header_value
        # Add session-specific parameters
        if rule.type == RuleType.SESSION_MANAGEMENT:
            if rule.max_requests is not None:
                rule_dict["max_requests"] = rule.max_requests
            if rule.max_blocked is not None:
                rule_dict["max_blocked"] = rule.max_blocked
            if rule.block_duration is not None:
                rule_dict["block_duration"] = rule.block_duration
            if rule.time_window is not None:
                rule_dict["time_window"] = rule.time_window
        # Add IP-based header manipulation parameters
        if rule.type == RuleType.HEADER_MANIPULATION and rule.suspicious_ips is not None:
            rule_dict["suspicious_ips"] = rule.suspicious_ips
        compiled_rules[rule.id] = rule_dict
        await es.index(index=rules_index, document=rule_dict, id=rule.id)
        return {"message": "Rule created successfully", "id": rule.id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid rule: {str(e)}")

@app.put("/api/waf/{domain}/rules/{rule_id}")
async def update_domain_rule(domain: str, rule_id: str, rule_update: RuleUpdate, request: Request):
    rules_index = f"{domain}_rules"
    es = request.app.state.esAuth
    
    try:
        # Get current rule
        current_rule = await es.get(index=rules_index, id=rule_id)
        rule_dict = current_rule["_source"]
        
        # Update fields
        if rule_update.type is not None:
            rule_dict["type"] = rule_update.type
        if rule_update.subtype is not None:
            # Only update subtype for header-manipulation and session-management rules
            if rule_update.type in [RuleType.HEADER_MANIPULATION, RuleType.SESSION_MANIPULATION] or rule_dict["type"] in ["header-manipulation", "session-management"]:
                rule_dict["subtype"] = rule_update.subtype
            else:
                # Remove subtype for security-pattern rules
                rule_dict.pop("subtype", None)
        if rule_update.pattern is not None:
            rule_dict["pattern"] = rule_update.pattern
        if rule_update.action is not None:
            rule_dict["action"] = rule_update.action
        if rule_update.severity is not None:
            rule_dict["severity"] = rule_update.severity
        if rule_update.description is not None:
            rule_dict["description"] = rule_update.description
        if rule_update.enabled is not None:
            rule_dict["enabled"] = rule_update.enabled
        if rule_update.header_name is not None:
            rule_dict["header_name"] = rule_update.header_name
        if rule_update.header_value is not None:
            rule_dict["header_value"] = rule_update.header_value
        
        # Handle session-specific parameters (check current rule type, not update type)
        if rule_dict.get("type") == "session-management":
            if rule_update.max_requests is not None:
                rule_dict["max_requests"] = rule_update.max_requests
            if rule_update.max_blocked is not None:
                rule_dict["max_blocked"] = rule_update.max_blocked
            if rule_update.block_duration is not None:
                rule_dict["block_duration"] = rule_update.block_duration
            if rule_update.time_window is not None:
                rule_dict["time_window"] = rule_update.time_window
        
        # Handle IP-based header manipulation parameters
        if rule_update.suspicious_ips is not None:
            rule_dict["suspicious_ips"] = rule_update.suspicious_ips

        await es.index(index=rules_index, document=rule_dict, id=rule_id)
        return {"message": "Rule updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=404, detail="Rule not found")

@app.delete("/api/waf/{domain}/rules/{rule_id}")
async def delete_domain_rule(domain: str, rule_id: str, request: Request):
    rules_index = f"{domain}_rules"
    policies_index = f"{domain}_policies"
    es = request.app.state.esAuth
    
    try:
        # Delete rule
        await es.delete(index=rules_index, id=rule_id)
        
        # Update policies that reference this rule
        policies = await get_domain_policies(domain, es)
        for policy_id, policy in policies.items():
            if rule_id in policy["rules"]:
                policy["rules"].remove(rule_id)
                await es.index(index=policies_index, document=policy, id=policy_id)
        
        return {"message": "Rule deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=404, detail="Rule not found")

# Domain-specific Policy Management
@app.get("/api/waf/{domain}/policies", response_model=List[Dict[str, Any]])
async def get_domain_policies_endpoint(domain: str, request: Request):
    policies = await get_domain_policies(domain, request.app.state.esAuth)
    return list(policies.values())

@app.post("/api/waf/{domain}/policies", status_code=201)
async def create_domain_policy(domain: str, policy: Policy, request: Request):
    policies_index = f"{domain}_policies"
    es = request.app.state.esAuth
    
    # Check if policy exists
    try:
        exists = await es.exists(index=policies_index, id=policy.id)
        if exists:
            raise HTTPException(status_code=400, detail="Policy ID already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Verify all rules exist
    rules = await get_domain_rules(domain, es)
    print(f"Available rules for domain {domain}: {list(rules.keys())}")
    print(f"Policy trying to use rules: {policy.rules}")
    
    missing_rules = []
    for rule_id in policy.rules:
        if rule_id not in rules:
            missing_rules.append(rule_id)
    
    if missing_rules:
        raise HTTPException(
            status_code=400, 
            detail=f"Rules not found: {', '.join(missing_rules)}. Available rules: {', '.join(rules.keys())}"
        )

    try:
        policy_dict = {
            "id": policy.id,
            "name": policy.name,
            "rules": policy.rules,
            "description": policy.description,
            "enabled": policy.enabled
        }
        await es.index(index=policies_index, document=policy_dict, id=policy.id)
        return {"message": "Policy created successfully", "id": policy.id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid policy: {str(e)}")

@app.put("/api/waf/{domain}/policies/{policy_id}")
async def update_domain_policy(domain: str, policy_id: str, policy_update: PolicyUpdate, request: Request):
    policies_index = f"{domain}_policies"
    es = request.app.state.esAuth
    
    try:
        # Get current policy
        current_policy = await es.get(index=policies_index, id=policy_id)
        policy_dict = current_policy["_source"]
        
        # Update fields only if provided
        if policy_update.name is not None:
            policy_dict["name"] = policy_update.name
        if policy_update.description is not None:
            policy_dict["description"] = policy_update.description
        if policy_update.enabled is not None:
            policy_dict["enabled"] = policy_update.enabled
        if policy_update.rules is not None:
            # Verify all rules exist before updating
            rules = await get_domain_rules(domain, es)
            for rule_id in policy_update.rules:
                if rule_id not in rules:
                    raise HTTPException(status_code=400, detail=f"Rule {rule_id} does not exist")
            policy_dict["rules"] = policy_update.rules

        await es.index(index=policies_index, document=policy_dict, id=policy_id)
        return {"message": "Policy updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=404, detail="Policy not found")

@app.delete("/api/waf/{domain}/policies/{policy_id}")
async def delete_domain_policy(domain: str, policy_id: str, request: Request):
    policies_index = f"{domain}_policies"
    es = request.app.state.esAuth
    
    try:
        await es.delete(index=policies_index, id=policy_id)
        return {"message": "Policy deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=404, detail="Policy not found")

# Session management endpoints
@app.get("/api/sessions/{domain}")
async def get_domain_sessions(domain: str):
    """Get all active sessions for a specific domain"""
    redis = app.state.redis
    sessions = []
    
    # Get domain-specific session keys
    keys = await redis.keys(f"session:{domain}:*")
    
    for key in keys:
        pickled = await redis.get(key)
        if pickled:
            sess: SessionData = pickle.loads(pickled)
            sessions.append({
                "session_id": key.decode().split(":")[2],  # Get session ID after domain
                "ip_address": sess.ip_address,
                "user_agent": sess.user_agent,
                "request_count": sess.request_count,
                "blocked_count": sess.blocked_count,
                "first_seen": sess.first_seen.isoformat(),
                "last_seen": sess.last_seen.isoformat(),
                "request_patterns": sess.request_patterns,
                "blocked_requests": sess.blocked_requests
            })
    
    return {"domain": domain, "sessions": sessions}

@app.get("/api/sessions/{domain}/{session_id}")
async def get_domain_session(domain: str, session_id: str):
    """Get specific session details for a domain"""
    redis = app.state.redis
    pickled = await redis.get(f"session:{domain}:{session_id}")
    
    if not pickled:
        raise HTTPException(status_code=404, detail="Session not found")
    
    sess: SessionData = pickle.loads(pickled)
    return {
        "domain": domain,
        "session_id": session_id,
        "ip_address": sess.ip_address,
        "user_agent": sess.user_agent,
        "request_count": sess.request_count,
        "blocked_count": sess.blocked_count,
        "first_seen": sess.first_seen.isoformat(),
        "last_seen": sess.last_seen.isoformat(),
        "request_patterns": sess.request_patterns,
        "blocked_requests": sess.blocked_requests
    }

@app.get("/api/sessions/{domain}/stats")
async def get_domain_session_stats(domain: str):
    """Get session statistics for a specific domain"""
    redis = app.state.redis
    sessions_data = []

#Get domain-specific session keys
    keys = await redis.keys(f"session:{domain}:*")

    for key in keys:
        pickled = await redis.get(key)
        if pickled:
            sess: SessionData = pickle.loads(pickled)

#Calculate session duration
            duration_minutes, idle_time, session_status = calculate_session_duration(sess)

            sessions_data.append({
                "ip_address": sess.ip_address,
                "session_duration": f"{duration_minutes:.1f} minutes",
                "last_seen": sess.last_seen.isoformat()
            })

    return {
        "domain": domain,
        "sessions": sessions_data
    }
# Keep the global endpoints for backward compatibility
@app.get("/api/sessions")
async def get_all_sessions():
    """Get all active sessions across all domains"""
    redis = app.state.redis
    sessions = []
    
    # Get all session keys
    keys = await redis.keys("session:*")
    
    for key in keys:
        pickled = await redis.get(key)
        if pickled:
            sess: SessionData = pickle.loads(pickled)
            domain = key.decode().split(":")[1]  # Get domain from key
            sessions.append({
                "domain": domain,
                "session_id": key.decode().split(":")[2],
                "ip_address": sess.ip_address,
                "user_agent": sess.user_agent,
                "request_count": sess.request_count,
                "blocked_count": sess.blocked_count,
                "first_seen": sess.first_seen.isoformat(),
                "last_seen": sess.last_seen.isoformat(),
                "request_patterns": sess.request_patterns,
                "blocked_requests": sess.blocked_requests
            })
    
    return {"sessions": sessions}


# @app.get("/api/sessions/{domain}/ip/{ip_address}")
# async def get_sessions_by_ip(domain: str, ip_address: str):
#     """Get all sessions for a specific IP address"""
#     redis = app.state.redis
#     sessions = []
    
#     # Get domain-specific session keys
#     keys = await redis.keys(f"session:{domain}:*")
    
#     for key in keys:
#         pickled = await redis.get(key)
#         if pickled:
#             sess: SessionData = pickle.loads(pickled)
#             if sess.ip_address == ip_address:
#                 session_id = key.decode().split(":")[2]
                
#                 # Use improved duration calculation
#                 duration_minutes, idle_time, session_status = calculate_session_duration(sess)
                
#                 # Get attack types
#                 attack_types = list(set(req["rule_id"] for req in sess.blocked_requests))
                
#                 # Get targets
#                 targets = list(sess.request_patterns.keys())
                
#                 sessions.append({
#                     "session_id": session_id,
#                     "ip_address": sess.ip_address,
#                     "total_attacks": sess.blocked_count,
#                     "attack_types": attack_types,
#                     "targets": targets,
#                     "duration": f"{duration_minutes:.1f} minutes",
#                     "idle_time": idle_time,
#                     "session_status": session_status,
#                     "first_seen": sess.first_seen.isoformat(),
#                     "last_seen": sess.last_seen.isoformat(),
#                     "user_agent": sess.user_agent,
#                     "request_count": sess.request_count
#                 })
    
    return {"domain": domain, "ip_address": ip_address, "sessions": sessions}

@app.get("/api/sessions/{domain}/session/{session_id}/detailed")
async def get_detailed_session_info(domain: str, session_id: str):
    """Get detailed session information including security analysis"""
    redis = app.state.redis
    pickled = await redis.get(f"session:{domain}:{session_id}")
    
    if not pickled:
        raise HTTPException(status_code=404, detail="Session not found")
    
    sess: SessionData = pickle.loads(pickled)
    
    # Use improved duration calculation
    duration_minutes, idle_time, session_status = calculate_session_duration(sess)
    
    # Get attack types
    attack_types = list(set(req["rule_id"] for req in sess.blocked_requests))
    
    # Get targets
    targets = list(sess.request_patterns.keys())
    
    # Calculate attack rate using accurate duration
    attack_rate = sess.blocked_count / duration_minutes if duration_minutes > 0 else 0
    
    # Determine threat level
    if sess.blocked_count > 10 or attack_rate > 5:
        threat_level = "HIGH"
    elif sess.blocked_count > 5 or attack_rate > 2:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"
    
    # Analyze attack sophistication
    if len(attack_types) >= 3:
        sophistication = "HIGH - Multiple attack vectors"
    elif len(attack_types) == 2:
        sophistication = "MEDIUM - Two attack types"
    else:
        sophistication = "LOW - Single attack type"
    
    # Analyze persistence
    if attack_rate > 10:
        persistence = "HIGH - Automated attack"
    elif attack_rate > 2:
        persistence = "MEDIUM - Semi-automated"
    else:
        persistence = "LOW - Manual testing"
    
    # Analyze target focus
    login_attempts = sess.request_patterns.get("/login.php", 0)
    admin_attempts = sess.request_patterns.get("/admin.php", 0)
    
    if admin_attempts > 0:
        target_focus = "ADMIN TARGETING"
    elif login_attempts > 10:
        target_focus = "LOGIN BRUTEFORCE"
    else:
        target_focus = "GENERAL RECONNAISSANCE"
    
    # Get last activity timestamp
    if sess.request_timestamps:
        last_activity = max(sess.request_timestamps)
        last_activity_str = last_activity.isoformat()
    else:
        last_activity = sess.last_seen
        last_activity_str = last_activity.isoformat()
    
    return {
        "session_id": session_id,
        "ip_address": sess.ip_address,
        "total_attacks": sess.blocked_count,
        "attack_types": attack_types,
        "targets": targets,
        "duration": f"{duration_minutes:.1f} minutes",
        "idle_time": idle_time,
        "session_status": session_status,
        "attack_rate_per_minute": f"{attack_rate:.2f}",
        "threat_level": threat_level,
        "attack_sophistication": sophistication,
        "persistence_level": persistence,
        "target_focus": target_focus,
        "first_seen": sess.first_seen.isoformat(),
        "last_seen": sess.last_seen.isoformat(),
        "last_activity": last_activity_str,
        "ended_at": sess.ended_at.isoformat() if sess.ended_at else None,
        "user_agent": sess.user_agent,
        "request_count": sess.request_count,
        "blocked_requests": sess.blocked_requests,
        "request_patterns": sess.request_patterns
    }

# @app.get("/api/sessions/{domain}/threats")
# async def get_domain_threats(domain: str):
#     """Get threat analysis for all sessions in a domain"""
#     redis = app.state.redis
#     sessions = []
    
#     # Get domain-specific session keys
#     keys = await redis.keys(f"session:{domain}:*")
    
#     for key in keys:
#         pickled = await redis.get(key)
#         if pickled:
#             sess: SessionData = pickle.loads(pickled)
#             session_id = key.decode().split(":")[2]
            
#             # Only include sessions with attacks
#             if sess.blocked_count > 0:
#                 # Use improved duration calculation
#                 duration_minutes, idle_time, session_status = calculate_session_duration(sess)
                
#                 # Calculate attack rate using accurate duration
#                 attack_rate = sess.blocked_count / duration_minutes if duration_minutes > 0 else 0
                
#                 # Get attack types
#                 attack_types = list(set(req["rule_id"] for req in sess.blocked_requests))
                
#                 # Determine threat level
#                 if sess.blocked_count > 10 or attack_rate > 5:
#                     threat_level = "HIGH"
#                 elif sess.blocked_count > 5 or attack_rate > 2:
#                     threat_level = "MEDIUM"
#                 else:
#                     threat_level = "LOW"
                
#                 sessions.append({
#                     "session_id": session_id,
#                     "ip_address": sess.ip_address,
#                     "total_attacks": sess.blocked_count,
#                     "attack_types": attack_types,
#                     "attack_rate_per_minute": f"{attack_rate:.2f}",
#                     "threat_level": threat_level,
#                     "duration": f"{duration_minutes:.1f} minutes",
#                     "idle_time": idle_time,
#                     "session_status": session_status,
#                     "first_seen": sess.first_seen.isoformat(),
#                     "last_seen": sess.last_seen.isoformat(),
#                     "user_agent": sess.user_agent
#                 })
    
#     # Sort by threat level (HIGH first, then MEDIUM, then LOW)
#     threat_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
#     sessions.sort(key=lambda x: threat_order.get(x["threat_level"], 0), reverse=True)
    
#     return {
#         "domain": domain,
#         "total_threat_sessions": len(sessions),
#         "threats": sessions
#     }

# ------------------------------------------------------------
# Session Fingerprint Generation
# ------------------------------------------------------------
def generate_session_fingerprint(domain: str, ip_address: str, user_agent: str) -> str:
    """
    Generate a unique session fingerprint based on domain, IP, and user agent.
    This prevents cookie clearing bypass by tying sessions to client characteristics.
    """
    # Create a hash of the client characteristics
    fingerprint_data = f"{domain}:{ip_address}:{user_agent}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]  # Use first 16 chars for readability

@app.get("/api/sessions/{domain}/fingerprint/{fingerprint}")
async def get_sessions_by_fingerprint(domain: str, fingerprint: str):
    """Get all sessions for a specific fingerprint (IP + User Agent combination)"""
    redis = app.state.redis
    sessions = []
    
    # Get domain-specific session keys
    keys = await redis.keys(f"session:{domain}:{fingerprint}*")
    
    for key in keys:
        pickled = await redis.get(key)
        if pickled:
            sess: SessionData = pickle.loads(pickled)
            session_id = key.decode().split(":")[2]
            
            # Use improved duration calculation
            duration_minutes, idle_time, session_status = calculate_session_duration(sess)
            
            # Get attack types
            attack_types = list(set(req["rule_id"] for req in sess.blocked_requests))
            
            # Get targets
            targets = list(sess.request_patterns.keys())
            
            sessions.append({
                "session_id": session_id,
                "ip_address": sess.ip_address,
                "user_agent": sess.user_agent,
                "total_attacks": sess.blocked_count,
                "attack_types": attack_types,
                "targets": targets,
                "duration": f"{duration_minutes:.1f} minutes",
                "idle_time": idle_time,
                "session_status": session_status,
                "first_seen": sess.first_seen.isoformat(),
                "last_seen": sess.last_seen.isoformat(),
                "request_count": sess.request_count
            })
    
    return {"domain": domain, "fingerprint": fingerprint, "sessions": sessions}

##############################################################################################################################################
# @app.get("/health")
# async def health_check():
#     """Health check endpoint to verify the application is running in HTTPS-only mode."""
#     ssl_available = (os.path.exists(SSL_CERT_FILE) and
#                      os.path.exists(SSL_KEY_FILE) and
#                      os.path.getsize(SSL_CERT_FILE) > 0 and
#                      os.path.getsize(SSL_KEY_FILE) > 0)
#
#     return {
#         "status": "healthy" if ssl_available else "unhealthy",
#         "mode": "HTTPS-only",
#         "timestamp": datetime.now().isoformat(),
#         "ssl_available": ssl_available,
#         "ssl_required": True,
#         "certificate_path": SSL_CERT_FILE,
#         "key_path": SSL_KEY_FILE,
#         "users_loaded": len(app.state.users) if hasattr(app.state, 'users') else 0,
#         "available_domains": list(app.state.users.keys()) if hasattr(app.state, 'users') else [],
#         "message": "Application running in HTTPS-only mode" if ssl_available else "SSL certificates required but not found"
#     }
#
#
#
# # ------------------------------------------------------------
# # Certificate Management API Endpoints
# # ------------------------------------------------------------
#
# @app.get("/api/certificates/status")
# async def get_certificate_status(domain: Optional[str] = None):
#     """Get the status of SSL certificates."""
#     try:
#         status = check_certificate_status(domain)
#         return status
#     except Exception as e:
#         logger.error(f"Error getting certificate status: {e}")
#         raise HTTPException(status_code=500, detail=f"Error getting certificate status: {str(e)}")
#
# @app.get("/api/certificates/info")
# async def get_certificate_info_endpoint(domain: Optional[str] = None):
#     """Get detailed certificate information."""
#     try:
#         if domain is None:
#             domain = DOMAIN_NAME
#
#         # For domain-specific certificates, look in the domain-specific directory
#         if domain != DOMAIN_NAME:
#             cert_path = os.path.join(CERT_DIR, 'live', domain, 'fullchain.pem')
#         else:
#             # For the primary domain, use the main SSL path
#             cert_path = SSL_CERT_FILE
#
#         if not os.path.exists(cert_path):
#             raise HTTPException(status_code=404, detail="Certificate not found")
#
#         cert_info = get_certificate_info(cert_path)
#         if not cert_info:
#             raise HTTPException(status_code=500, detail="Error reading certificate information")
#
#         return cert_info
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error getting certificate info: {e}")
#         raise HTTPException(status_code=500, detail=f"Error getting certificate info: {str(e)}")
#
# @app.get("/api/certificates/config")
# async def get_certificate_config():
#     """Get current certificate configuration."""
#     try:
#         config = load_certificate_config()
#         if not config:
#             raise HTTPException(status_code=500, detail="Error loading certificate configuration")
#         return config
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error getting certificate config: {e}")
#         raise HTTPException(status_code=500, detail=f"Error getting certificate config: {str(e)}")
#
# @app.put("/api/certificates/config")
# async def update_certificate_config_endpoint(config: CertificateConfig):
#     """Update certificate configuration."""
#     try:
#         if not is_admin():
#             raise HTTPException(status_code=403, detail="Administrative privileges required")
#
#         success = update_certificate_config(config)
#         if not success:
#             raise HTTPException(status_code=400, detail="Invalid certificate configuration")
#
#         return {"message": "Certificate configuration updated successfully", "config": config}
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error updating certificate config: {e}")
#         raise HTTPException(status_code=500, detail=f"Error updating certificate config: {str(e)}")
#
# @app.delete("/api/certificates")
# async def delete_certificates_endpoint(domain: Optional[str] = None):
#     """Delete SSL certificates."""
#     try:
#         if not is_admin():
#             raise HTTPException(status_code=403, detail="Administrative privileges required")
#
#         success = delete_certificates(domain)
#         if not success:
#             raise HTTPException(status_code=500, detail="Failed to delete certificates")
#
#         return {"message": "Certificates deleted successfully"}
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error deleting certificates: {e}")
#         raise HTTPException(status_code=500, detail=f"Error deleting certificates: {str(e)}")
#
# @app.post("/api/certificates/test-duckdns")
# async def test_duckdns_connection_endpoint(token: str):
#     """Test DuckDNS API connection."""
#     try:
#         success = test_duckdns_connection(token)
#         return {
#             "success": success,
#             "message": "DuckDNS connection test completed"
#         }
#     except Exception as e:
#         logger.error(f"Error testing DuckDNS connection: {e}")
#         raise HTTPException(status_code=500, detail=f"Error testing DuckDNS connection: {str(e)}")
#
# @app.get("/api/certificates/logs")
# async def get_certificate_logs_endpoint():
#     """Get certificate-related logs."""
#     try:
#         logs = get_certificate_logs()
#         return {
#             "logs": logs,
#             "count": len(logs)
#         }
#     except Exception as e:
#         logger.error(f"Error getting certificate logs: {e}")
#         raise HTTPException(status_code=500, detail=f"Error getting certificate logs: {str(e)}")
#
# @app.get("/api/certificates/health")
# async def certificate_health_check():
#     """Health check for certificate management."""
#     try:
#         status = check_certificate_status()
#         config = load_certificate_config()
#
#         return {
#             "certificate_status": status,
#             "configuration": config,
#             "admin_privileges": is_admin(),
#             "ssl_available": (os.path.exists(SSL_CERT_FILE) and
#                              os.path.exists(SSL_KEY_FILE) and
#                              os.path.getsize(SSL_CERT_FILE) > 0 and
#                              os.path.getsize(SSL_KEY_FILE) > 0),
#             "timestamp": datetime.now().isoformat()
#         }
#     except Exception as e:
#         logger.error(f"Error in certificate health check: {e}")
#         raise HTTPException(status_code=500, detail=f"Error in certificate health check: {str(e)}")
#
#
# # ------------------------------------------------------------
# # Dynamic Certificate Management API Endpoints
# # ------------------------------------------------------------
#
# @app.post("/api/certificates/validate")
# async def validate_certificate_request(request: CertificateCreationRequest):
#     """Validate certificate creation request parameters."""
#     try:
#         validation = validate_certificate_creation_request(request)
#         return validation
#     except Exception as e:
#         logger.error(f"Error validating certificate request: {e}")
#         raise HTTPException(status_code=500, detail=f"Error validating certificate request: {str(e)}")
#
# @app.post("/api/certificates/create")
# async def create_certificate_dynamic(request: CertificateCreationRequest):
#     """Create SSL certificates with dynamic parameters from frontend."""
#     try:
#         if not is_admin():
#             raise HTTPException(status_code=403, detail="Administrative privileges required")
#
#         # Validate the request first
#         validation = validate_certificate_creation_request(request)
#         if not (validation.domain_valid and validation.token_valid and validation.domain_available):
#             raise HTTPException(status_code=400, detail=f"Validation failed: {validation.message}")
#
#         # Attempt certificate creation
#         result = setup_letsencrypt_dynamic(
#             domain_name=request.domain_name,
#             email=request.email,
#             duckdns_token=request.duckdns_token,
#             force_renewal=request.force_renewal
#         )
#
#         if result.success:
#             return result
#         else:
#             raise HTTPException(status_code=500, detail=result.message)
#
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error creating certificate: {e}")
#         raise HTTPException(status_code=500, detail=f"Error creating certificate: {str(e)}")
#
# @app.post("/api/certificates/renew-dynamic")
# async def renew_certificate_dynamic(request: CertificateCreationRequest):
#     """Renew SSL certificates with dynamic parameters."""
#     try:
#         if not is_admin():
#             raise HTTPException(status_code=403, detail="Administrative privileges required")
#
#         # Validate the request first
#         validation = validate_certificate_creation_request(request)
#         if not (validation.domain_valid and validation.token_valid and validation.domain_available):
#             raise HTTPException(status_code=400, detail=f"Validation failed: {validation.message}")
#
#         # Attempt certificate renewal
#         result = renew_certificates_dynamic(
#             domain_name=request.domain_name,
#             email=request.email,
#             duckdns_token=request.duckdns_token,
#             force=request.force_renewal
#         )
#
#         if result.success:
#             return result
#         else:
#             raise HTTPException(status_code=500, detail=result.message)
#
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error renewing certificate: {e}")
#         raise HTTPException(status_code=500, detail=f"Error renewing certificate: {str(e)}")
#
# @app.delete("/api/certificates/dynamic")
# async def delete_certificate_dynamic(domain: str):
#     """Delete SSL certificates for a specific domain."""
#     try:
#         if not is_admin():
#             raise HTTPException(status_code=403, detail="Administrative privileges required")
#
#         if not domain:
#             raise HTTPException(status_code=400, detail="Domain parameter is required")
#
#         # Validate domain format
#         if not domain or '.' not in domain:
#             raise HTTPException(status_code=400, detail="Invalid domain format")
#
#         # Attempt certificate deletion
#         result = delete_certificates_dynamic(domain)
#
#         if result.success:
#             return result
#         else:
#             raise HTTPException(status_code=500, detail=result.message)
#
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error deleting certificate: {e}")
#         raise HTTPException(status_code=500, detail=f"Error deleting certificate: {str(e)}")
#
# @app.post("/api/certificates/test-duckdns-dynamic")
# async def test_duckdns_connection_dynamic(request: CertificateValidationRequest):
#     """Test DuckDNS connection with dynamic token."""
#     try:
#         if not request.duckdns_token:
#             raise HTTPException(status_code=400, detail="DuckDNS token is required")
#
#         success = test_duckdns_connection(request.duckdns_token, request.domain_name)
#
#         return {
#             "success": success,
#             "message": "DuckDNS connection test completed",
#             "domain": request.domain_name,
#             "token_valid": len(request.duckdns_token) >= 10
#         }
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error testing DuckDNS connection: {e}")
#         raise HTTPException(status_code=500, detail=f"Error testing DuckDNS connection: {str(e)}")
#
# @app.get("/api/certificates/domains")
# async def get_managed_domains():
#     """Get list of all managed domains and their certificate status."""
#     try:
#         managed_domains = []
#
#         # Check the main certificate directory
#         live_dir = os.path.join(CERT_DIR, 'live')
#         if os.path.exists(live_dir):
#             for domain_dir in os.listdir(live_dir):
#                 domain_path = os.path.join(live_dir, domain_dir)
#                 if os.path.isdir(domain_path):
#                     cert_path = os.path.join(domain_path, 'fullchain.pem')
#                     key_path = os.path.join(domain_path, 'privkey.pem')
#
#                     if os.path.exists(cert_path) and os.path.exists(key_path):
#                         status = check_certificate_status(domain_dir)
#                         managed_domains.append({
#                             "domain": domain_dir,
#                             "status": status,
#                             "is_primary": domain_dir == DOMAIN_NAME
#                         })
#
#         return {
#             "managed_domains": managed_domains,
#             "total_domains": len(managed_domains),
#             "primary_domain": DOMAIN_NAME
#         }
#     except Exception as e:
#         logger.error(f"Error getting managed domains: {e}")
#         raise HTTPException(status_code=500, detail=f"Error getting managed domains: {str(e)}")
#
# @app.post("/api/certificates/operation-status")
# async def get_operation_status(operation_id: str):
#     """Get the status of a certificate operation."""
#     try:
#         # This is a simplified implementation - in a real system, you might store operation status in a database
#         # For now, we'll return a basic response
#         return {
#             "operation_id": operation_id,
#             "status": "completed",  # This would be dynamic in a real implementation
#             "message": "Operation completed successfully",
#             "timestamp": datetime.now().isoformat()
#         }
#     except Exception as e:
#         logger.error(f"Error getting operation status: {e}")
#         raise HTTPException(status_code=500, detail=f"Error getting operation status: {str(e)}")

##############################################################################################################################################
if __name__ == "__main__":
    uvicorn.run("reverse_prx:app", host="0.0.0.0", port=443, reload=True)

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Relaunch the script with administrative privileges."""
    if os.name == 'nt' and not is_admin():
        # Create a temporary VBS script to handle UAC elevation
        vbs_script = os.path.join(tempfile.gettempdir(), 'elevate.vbs')
        with open(vbs_script, 'w') as f:
            f.write(f'''
Set objShell = CreateObject("Shell.Application")
objShell.ShellExecute "{sys.executable}", "{" ".join(sys.argv)}", "", "runas", 1
''')

        try:
            # Run the VBS script
            subprocess.run(['cscript', '//nologo', vbs_script],
                         creationflags=subprocess.CREATE_NO_WINDOW)
            # Exit the current process
            sys.exit(0)
        finally:
            # Clean up the VBS script
            try:
                os.remove(vbs_script)
            except:
                pass

#Attempt to elevate privileges at startup
run_as_admin()  # Enable automatic privilege elevation at startup

DOMAIN_NAME = os.getenv("DOMAIN_NAME", "testswaf.duckdns.org")

#Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.getenv("CERT_DIR", os.path.join(SCRIPT_DIR, "letsencrypt"))
CERT_PATH = os.path.join(CERT_DIR, DOMAIN_NAME)

SSL_CERT_FILE = os.path.join(SCRIPT_DIR, "fullchain.pem")
SSL_KEY_FILE = os.path.join(SCRIPT_DIR, "privkey.pem")
ES_CA_CERT = os.getenv("ES_CA_CERT", "C:/Windows/System32/certificates/ca-certificates.crt")


def is_port_in_use(port):
    """Check if a port is in use."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('0.0.0.0', port))
            return False
        except socket.error:
            return True


def find_available_port(start_port=8000):
    """Find an available port starting from start_port."""
    port = start_port
    while is_port_in_use(port):
        port += 1
    return port


def start_server():
    """Start the FastAPI server with HTTP to HTTPS redirection."""
    try:
        # Check if SSL certificates exist and are valid
        ssl_available = (os.path.exists(SSL_CERT_FILE) and
                         os.path.exists(SSL_KEY_FILE) and
                         os.path.getsize(SSL_CERT_FILE) > 0 and
                         os.path.getsize(SSL_KEY_FILE) > 0)

        if not ssl_available:
            logger.error("❌ SSL certificates not found or invalid!")
            logger.error("This application requires SSL certificates for HTTPS redirection.")
            logger.error("Please create SSL certificates first using one of these methods:")
            logger.error("1. Use the certificate API: POST /api/certificates/create")
            logger.error("2. Manually place fullchain.pem and privkey.pem in the application directory")
            logger.error("3. Set up certificates using the certificate management endpoints")
            logger.error("")
            logger.error("Certificate files expected:")
            logger.error(f"  Certificate: {SSL_CERT_FILE}")
            logger.error(f"  Private Key: {SSL_KEY_FILE}")
            logger.error("")
            logger.error("The application will not start without valid SSL certificates.")
            sys.exit(1)

        logger.info("✅ SSL certificates found. Setting up HTTP to HTTPS redirection...")

        if not is_admin():
            logger.error("❌ HTTP/HTTPS redirection requires administrative privileges!")
            logger.error("Please run the application as administrator to use ports 80 and 443.")
            logger.error("Alternatively, you can run on different ports with:")
            logger.error("  uvicorn reverse_prx:app --host 0.0.0.0 --port 8080")
            logger.error(
                "  uvicorn reverse_prx:app --host 0.0.0.0 --port 8443 --ssl-keyfile privkey.pem --ssl-certfile fullchain.pem")
            sys.exit(1)

        # Check if ports are available
        if is_port_in_use(80):
            logger.error("❌ Port 80 is already in use!")
            logger.error("Please free up port 80 for HTTP redirection.")
            sys.exit(1)

        if is_port_in_use(443):
            logger.error("❌ Port 443 is already in use!")
            logger.error("Please free up port 443 for HTTPS.")
            sys.exit(1)

        # Start both HTTP and HTTPS servers
        logger.info("🚀 Starting HTTP to HTTPS redirection setup...")
        logger.info("   HTTP server (port 80) will redirect to HTTPS")
        logger.info("   HTTPS server (port 443) will serve the application")

        # Start HTTPS server in background
        def start_https_server():
            uvicorn.run(
                "reverse_prx:app",
                host="0.0.0.0",
                port=443,
                ssl_keyfile=SSL_KEY_FILE,
                ssl_certfile=SSL_CERT_FILE,
                reload=False,
                log_level="info"
            )

        # Start HTTP redirect server
        def start_http_redirect_server():
            from fastapi import FastAPI, Request
            from fastapi.responses import RedirectResponse

            redirect_app = FastAPI(title="HTTP to HTTPS Redirect")

            @redirect_app.middleware("http")
            async def redirect_to_https(request: Request, call_next):
                # Get the original URL and redirect to HTTPS
                host = request.headers.get("host", "").split(":")[0]
                https_url = f"https://{host}{request.url.path}"
                if request.url.query:
                    https_url += f"?{request.url.query}"
                return RedirectResponse(url=https_url, status_code=301)

            @redirect_app.get("/{full_path:path}")
            async def redirect_all(request: Request, full_path: str):
                host = request.headers.get("host", "").split(":")[0]
                https_url = f"https://{host}/{full_path}"
                return RedirectResponse(url=https_url, status_code=301)

            uvicorn.run(
                redirect_app,
                host="0.0.0.0",
                port=80,
                log_level="info"
            )

        # Start both servers in separate threads
        https_thread = threading.Thread(target=start_https_server, daemon=True)
        http_thread = threading.Thread(target=start_http_redirect_server, daemon=True)

        logger.info("Starting HTTP redirect server on port 80...")
        http_thread.start()

        logger.info("Starting HTTPS server on port 443...")
        https_thread.start()

        logger.info("✅ Both servers started successfully!")
        logger.info("   HTTP requests will automatically redirect to HTTPS")
        logger.info("   Access your application at: https://your-domain.com")

        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down servers...")

    except Exception as e:
        logger.error(f"❌ Error starting servers: {e}")
        logger.error("The application requires SSL certificates to run HTTP to HTTPS redirection.")
        sys.exit(1)


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

    # Start the server
    start_server()



