#!/usr/bin/env python3
"""
Shopist database seeding script
WARNING: intentionally contains hardcoded secrets for Secret Scanning demo
"""

import stripe
import boto3
import openai

# Stripe
stripe.api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"

# OpenAI
openai.api_key = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghijklmn"

# AWS
s3 = boto3.client(
    "s3",
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)

# Database
DB_URL = "postgresql://shopist_admin:Sup3rS3cr3tP@ssw0rd!@prod-db.shopist.internal:5432/shopist"

# HuggingFace (product recommendation model)
HUGGINGFACE_TOKEN = "hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678"

# Anthropic (AI assistant)
ANTHROPIC_API_KEY = "sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"

# PyPI token for publishing internal packages
PYPI_TOKEN = "pypi-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghijklmnopqrstuvwxyz12"

# Datadog
DD_API_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
DD_APP_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

if __name__ == "__main__":
    print("Seeding Shopist database...")
