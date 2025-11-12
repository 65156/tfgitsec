"""
Setup script for tfgitsec package
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text() if (this_directory / "README.md").exists() else ""

setup(
    name="tfgitsec",
    version="1.0.3",
    author="Your Name",
    author_email="your.email@example.com",
    description="Generate GitHub security issues from TfSec scan results",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/tfgitsec",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance", 
        "Topic :: Security",
        "Topic :: System :: System Shells",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.10",
            "black>=21.0",
            "isort>=5.0",
            "mypy>=0.910",
        ]
    },
    entry_points={
        "console_scripts": [
            "tfgitsec=tfgitsec.cli:main",
        ],
    },
    keywords="terraform tfsec security github issues automation devops",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/tfgitsec/issues",
        "Source": "https://github.com/yourusername/tfgitsec",
        "Documentation": "https://github.com/yourusername/tfgitsec/blob/main/README.md",
    },
)
