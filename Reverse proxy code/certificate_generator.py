#!/usr/bin/env python3
"""
Standalone Certificate Generator Script
======================================

This script allows you to generate SSL certificates using the same functions
as the main application, but without running the server.

Usage:
    python certificate_generator.py --domain your-domain.duckdns.org --email your-email@example.com --token your-duckdns-token
    python certificate_generator.py --config config.json
    python certificate_generator.py --status
    python certificate_generator.py --delete your-domain.duckdns.org
"""

import asyncio
import json
import os
import sys
import argparse
import logging
import subprocess
import time
import tempfile
import shutil
from datetime import datetime
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def print_banner():
    """Print a nice banner for the certificate generator."""
    print("=" * 60)
    print("🔐 SSL Certificate Generator")
    print("   Standalone certificate management tool")
    print("=" * 60)

def check_prerequisites():
    """Check if all prerequisites are met."""
    print("🔍 Checking prerequisites...")
    
    # Check admin privileges
    if not is_admin():
        print("❌ Administrative privileges required!")
        print("   Please run this script as administrator.")
        return False
    
    print("✅ Administrative privileges confirmed")
    
    # Check if certbot is installed
    try:
        result = subprocess.run(['certbot', '--version'], 
                              capture_output=True, text=True, 
                              creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0:
            print("✅ Certbot is installed")
            print(f"   Version: {result.stdout.strip()}")
        else:
            print("❌ Certbot is not properly installed")
            return False
    except Exception as e:
        print(f"❌ Error checking certbot: {e}")
        return False
    
    # Create certificate directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_dir = os.path.join(script_dir, "letsencrypt")
    if not os.path.exists(cert_dir):
        try:
            os.makedirs(cert_dir, exist_ok=True)
            print(f"✅ Created certificate directory: {cert_dir}")
        except Exception as e:
            print(f"❌ Error creating certificate directory: {e}")
            return False
    else:
        print(f"✅ Certificate directory exists: {cert_dir}")
    
    return True

def test_duckdns_connection(token: str, domain: str) -> bool:
    """Test DuckDNS API connection."""
    try:
        import requests
        # Extract domain name without .duckdns.org suffix
        domain_name = domain.replace('.duckdns.org', '')
        url = f"https://www.duckdns.org/update?domains={domain_name}&token={token}&ip=127.0.0.1"
        response = requests.get(url, timeout=10)
        print(f"   DuckDNS API URL: {url}")
        print(f"   Response status: {response.status_code}")
        print(f"   Response content: {response.text}")
        return response.status_code == 200 and "OK" in response.text
    except Exception as e:
        print(f"   Error testing DuckDNS: {e}")
        return False

def validate_input(domain: str, email: str, token: str) -> bool:
    """Validate input parameters."""
    print("🔍 Validating input parameters...")
    
    # Validate domain name
    domain_valid = bool(domain and '.' in domain and 'duckdns.org' in domain)
    print(f"   Domain valid: {'✅' if domain_valid else '❌'}")
    
    # Validate email
    email_valid = bool(email and '@' in email and '.' in email.split('@')[1])
    print(f"   Email valid: {'✅' if email_valid else '❌'}")
    
    # Validate DuckDNS token
    token_valid = bool(token and len(token) >= 10)
    print(f"   Token valid: {'✅' if token_valid else '❌'}")
    
    if not (domain_valid and email_valid and token_valid):
        print("❌ Basic validation failed")
        return False
    
    # Test DuckDNS connection
    print("   Testing DuckDNS connection...")
    domain_available = test_duckdns_connection(token, domain)
    print(f"   Domain available: {'✅' if domain_available else '❌'}")
    
    if not domain_available:
        print("❌ DuckDNS connection failed")
        return False
    
    print("✅ All parameters are valid")
    return True

def create_certificate(domain: str, email: str, token: str, force: bool = False) -> bool:
    """Create a certificate for the specified domain."""
    print(f"🔐 Creating certificate for {domain}...")
    
    try:
        # Get script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.join(script_dir, "letsencrypt")
        
        # Create domain-specific directories
        domain_cert_dir = os.path.join(cert_dir, 'live', domain)
        domain_work_dir = os.path.join(cert_dir, 'work', domain)
        domain_logs_dir = os.path.join(cert_dir, 'logs', domain)
        
        for dir_path in [domain_cert_dir, domain_work_dir, domain_logs_dir]:
            os.makedirs(dir_path, exist_ok=True)
            print(f"   Created directory: {dir_path}")
        
        # Check if certificates already exist
        domain_cert_path = os.path.join(domain_cert_dir, 'fullchain.pem')
        domain_key_path = os.path.join(domain_cert_dir, 'privkey.pem')
        
        if (os.path.exists(domain_cert_path) and 
            os.path.exists(domain_key_path) and 
            os.path.getsize(domain_cert_path) > 0 and 
            os.path.getsize(domain_key_path) > 0 and
            not force):
            
            print("✅ SSL certificates found and valid, skipping setup")
            return True
        
        # Create DuckDNS credentials file
        duckdns_creds = os.path.join(cert_dir, f'duckdns_{domain}.ini')
        with open(duckdns_creds, 'w') as f:
            f.write(f'''dns_duckdns_token = {token}
dns_duckdns_propagation_seconds = 60
''')
        print(f"   Created DuckDNS credentials file")
        
        # Run certbot
        certbot_cmd = [
            'certbot',
            'certonly',
            '--non-interactive',
            '--agree-tos',
            '--email', email,
            '--authenticator', 'dns-duckdns',
            '--dns-duckdns-credentials', duckdns_creds,
            '--dns-duckdns-propagation-seconds', '60',
            '-d', domain,
            '--config-dir', cert_dir,
            '--work-dir', domain_work_dir,
            '--logs-dir', domain_logs_dir,
            '--preferred-challenges', 'dns',
            '--debug'
        ]
        
        if force:
            certbot_cmd.append('--force-renewal')
        
        print(f"   Running certbot command...")
        process = subprocess.run(
            certbot_cmd,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Log output
        if process.stdout:
            print("   Certbot output:")
            for line in process.stdout.split('\n')[-5:]:  # Last 5 lines
                if line.strip():
                    print(f"     {line}")
        
        if process.stderr:
            print("   Certbot errors:")
            for line in process.stderr.split('\n')[-5:]:  # Last 5 lines
                if line.strip():
                    print(f"     {line}")
        
        if process.returncode != 0:
            print(f"❌ Certbot failed with return code {process.returncode}")
            return False
        
        # Wait for files to be created
        max_wait = 10
        wait_time = 0
        while wait_time < max_wait:
            if os.path.exists(domain_cert_path) and os.path.exists(domain_key_path):
                break
            time.sleep(1)
            wait_time += 1
            print(f"   Waiting for certificate files... ({wait_time}s)")
        
        if not os.path.exists(domain_cert_path) or not os.path.exists(domain_key_path):
            print(f"❌ Certificate files not found after {max_wait} seconds")
            return False
        
        print("✅ Certificate created successfully!")
        print(f"   Certificate path: {domain_cert_path}")
        print(f"   Key path: {domain_key_path}")
        
        # Copy to main directory
        ssl_cert_file = os.path.join(script_dir, "fullchain.pem")
        ssl_key_file = os.path.join(script_dir, "privkey.pem")
        
        try:
            shutil.copy2(domain_cert_path, ssl_cert_file)
            shutil.copy2(domain_key_path, ssl_key_file)
            print(f"   Certificates copied to main directory")
        except Exception as e:
            print(f"   Warning: Failed to copy to main directory: {e}")
        
        return True
    
    except Exception as e:
        print(f"❌ Error creating certificate: {e}")
        return False

def check_status(domain: str) -> bool:
    """Check certificate status."""
    print(f"🔍 Checking certificate status for {domain}...")
    
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.join(script_dir, "letsencrypt")
        
        # Check domain-specific certificate
        domain_cert_path = os.path.join(cert_dir, 'live', domain, 'fullchain.pem')
        domain_key_path = os.path.join(cert_dir, 'live', domain, 'privkey.pem')
        
        # Check main certificate
        ssl_cert_file = os.path.join(script_dir, "fullchain.pem")
        ssl_key_file = os.path.join(script_dir, "privkey.pem")
        
        exists = (os.path.exists(domain_cert_path) and os.path.exists(domain_key_path))
        main_exists = (os.path.exists(ssl_cert_file) and os.path.exists(ssl_key_file))
        
        print(f"   Domain: {domain}")
        print(f"   Domain certificate exists: {'✅' if exists else '❌'}")
        print(f"   Main certificate exists: {'✅' if main_exists else '❌'}")
        
        if exists:
            size = os.path.getsize(domain_cert_path)
            modified = datetime.fromtimestamp(os.path.getmtime(domain_cert_path)).isoformat()
            print(f"   Certificate path: {domain_cert_path}")
            print(f"   Key path: {domain_key_path}")
            print(f"   Size: {size} bytes")
            print(f"   Last modified: {modified}")
        
        if main_exists:
            size = os.path.getsize(ssl_cert_file)
            modified = datetime.fromtimestamp(os.path.getmtime(ssl_cert_file)).isoformat()
            print(f"   Main certificate path: {ssl_cert_file}")
            print(f"   Main key path: {ssl_key_file}")
            print(f"   Main size: {size} bytes")
            print(f"   Main last modified: {modified}")
        
        return exists or main_exists
    
    except Exception as e:
        print(f"❌ Error checking status: {e}")
        return False

def delete_certificate(domain: str) -> bool:
    """Delete certificate for the specified domain."""
    print(f"🗑  Deleting certificate for {domain}...")
    
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.join(script_dir, "letsencrypt")
        
        # Delete domain-specific certificate files
        domain_cert_dir = os.path.join(cert_dir, 'live', domain)
        domain_cert_path = os.path.join(domain_cert_dir, 'fullchain.pem')
        domain_key_path = os.path.join(domain_cert_dir, 'privkey.pem')
        
        deleted_files = []
        
        if os.path.exists(domain_cert_path):
            os.remove(domain_cert_path)
            deleted_files.append(domain_cert_path)
            print(f"   Deleted certificate file: {domain_cert_path}")
        
        if os.path.exists(domain_key_path):
            os.remove(domain_key_path)
            deleted_files.append(domain_key_path)
            print(f"   Deleted key file: {domain_key_path}")
        
        # Clean up certbot directories
        if os.path.exists(domain_cert_dir):
            shutil.rmtree(domain_cert_dir)
            deleted_files.append(domain_cert_dir)
            print(f"   Deleted certificate directory: {domain_cert_dir}")
        
        # Delete main certificate files
        ssl_cert_file = os.path.join(script_dir, "fullchain.pem")
        ssl_key_file = os.path.join(script_dir, "privkey.pem")
        
        if os.path.exists(ssl_cert_file):
            os.remove(ssl_cert_file)
            deleted_files.append(ssl_cert_file)
            print(f"   Deleted main certificate file: {ssl_cert_file}")
        
        if os.path.exists(ssl_key_file):
            os.remove(ssl_key_file)
            deleted_files.append(ssl_key_file)
            print(f"   Deleted main key file: {ssl_key_file}")
        
        print(f"✅ Successfully deleted {len(deleted_files)} files/directories")
        return True
    
    except Exception as e:
        print(f"❌ Error deleting certificate: {e}")
        return False

def save_config(domain: str, email: str, token: str, config_file: str = "cert_config.json"):
    """Save configuration to JSON file."""
    config = {
        "domain_name": domain,
        "email": email,
        "duckdns_token": token,
        "auto_renewal": True,
        "renewal_interval_hours": 24,
        "created_at": datetime.now().isoformat()
    }
    
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✅ Configuration saved to {config_file}")
    except Exception as e:
        print(f"❌ Error saving config: {e}")

def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from JSON file."""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        required_fields = ['domain_name', 'email', 'duckdns_token']
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required field: {field}")
        
        return config
    except Exception as e:
        print(f"❌ Error loading config file: {e}")
        sys.exit(1)

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Standalone SSL Certificate Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python certificate_generator.py --domain test.duckdns.org --email test@example.com --token your-token
  python certificate_generator.py --config my-config.json
  python certificate_generator.py --status --domain test.duckdns.org
  python certificate_generator.py --delete test.duckdns.org
        """
    )
    
    # Certificate creation options
    parser.add_argument("--domain", help="Domain name (e.g., test.duckdns.org)")
    parser.add_argument("--email", help="Email address for Let's Encrypt")
    parser.add_argument("--token", help="DuckDNS API token")
    parser.add_argument("--config", help="Load configuration from JSON file")
    parser.add_argument("--force", action="store_true", help="Force certificate renewal")
    
    # Other options
    parser.add_argument("--status", action="store_true", help="Check certificate status")
    parser.add_argument("--delete", help="Delete certificate for specified domain")
    parser.add_argument("--save-config", help="Save configuration to specified file")
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Handle different operations
    if args.status:
        if not args.domain:
            print("❌ --domain is required for status check")
            sys.exit(1)
        success = check_status(args.domain)
        sys.exit(0 if success else 1)
    
    elif args.delete:
        success = delete_certificate(args.delete)
        sys.exit(0 if success else 1)
    
    elif args.config:
        # Load from config file
        config = load_config(args.config)
        domain = config['domain_name']
        email = config['email']
        token = config['duckdns_token']
        
        print(f"📋 Loaded configuration:")
        print(f"   Domain: {domain}")
        print(f"   Email: {email}")
        print(f"   Token: {token[:10]}...{token[-4:]}")
        
        # Validate input
        if not validate_input(domain, email, token):
            sys.exit(1)
        
        # Create certificate
        success = create_certificate(domain, email, token, args.force)
        
        # Save config if requested
        if args.save_config:
            save_config(domain, email, token, args.save_config)
        
        sys.exit(0 if success else 1)
    
    elif args.domain and args.email and args.token:
        # Create certificate with command line arguments
        domain = args.domain
        email = args.email
        token = args.token
        
        # Validate input
        if not validate_input(domain, email, token):
            sys.exit(1)
        
        # Create certificate
        success = create_certificate(domain, email, token, args.force)
        
        # Save config if requested
        if args.save_config:
            save_config(domain, email, token, args.save_config)
        
        sys.exit(0 if success else 1)
    
    else:
        print("❌ No valid operation specified")
        print("   Use --help for usage information")
        sys.exit(1)

if __name__ == "__main__":
    main()