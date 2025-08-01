from setuptools import setup, find_packages

setup(
    name='pdforensic-authentic-check',
    version='0.1.0',
    description='A simple PDF forensic toolkit using pdfresurrect and bash utilities',
    author='Alex Mkwizu',
    author_email='alexgmkwizu@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[],  # Add any dependencies like PyPDF2 if used
    extras_require={
    "dev": ["pytest"]
    },
    entry_points={
        'console_scripts': [
            'pdf-meta=pdforensic.retrieve_metadata:cli',
            'pdf-recover=pdforensic.retrieve_all_versions:cli',
            'pdf-eof=pdforensic.check_eof_markers:cli',
            'pdf-versions=pdforensic.check_versions:cli'
        ],
    },
)
