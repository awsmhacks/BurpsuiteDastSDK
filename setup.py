#!/usr/bin/env python3
"""
Burp Suite DAST GraphQL API SDK - Setup Script
"""

from setuptools import setup, find_packages

with open("README_SDK.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="burpsuite-sdk",
    version="1.0.0",
    author="Generated from Burp Suite DAST GraphQL Schema",
    description="Python SDK for Burp Suite DAST GraphQL API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://portswigger.net/burp/enterprise",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Typing :: Typed",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "mypy>=1.0.0",
            "black>=23.0.0",
            "isort>=5.0.0",
        ],
    },
    package_data={
        "burpsuite_sdk": ["py.typed"],
    },
    include_package_data=True,
)

