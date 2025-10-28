#!/usr/bin/env python3
"""
Setup script for MiniShark
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="minishark",
    version="1.0.0",
    author="MiniShark Contributors",
    author_email="",
    description="A CLI-based network analysis tool similar to tshark",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/minishark",
    py_modules=["minishark"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "minishark=minishark:main",
        ],
    },
    keywords="network analysis, packet capture, tshark, wireshark, networking, cli",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/minishark/issues",
        "Source": "https://github.com/yourusername/minishark",
    },
)