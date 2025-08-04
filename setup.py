from setuptools import setup, find_packages
from setuptools.command.install import install
import os
import stat
import platform

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()


class CustomInstallCommand(install):
    """Custom install command to set executable permissions on binaries."""
    
    def run(self):
        install.run(self)
        # Set executable permissions for the appropriate binary based on OS
        system = platform.system().lower()
        if system == 'darwin':  # macOS
            binary_name = 'mac_pdfresurrect'
        elif system == 'linux':
            binary_name = 'linux_pdfresurrect'
        else:
            return  # Skip for other systems
        
        # Find the installed binary and set permissions
        for root, dirs, files in os.walk(self.install_base):
            for file in files:
                if file == binary_name:
                    file_path = os.path.join(root, file)
                    try:
                        current_permissions = os.stat(file_path).st_mode
                        new_permissions = current_permissions | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                        os.chmod(file_path, new_permissions)
                        print(f"Set executable permissions for {file_path}")
                    except Exception as e:
                        print(f"Warning: Could not set executable permissions for {file_path}: {e}")


setup(
    name='pdforensic-authentic-check',
    version='0.1.41',
    description='A simple PDF forensic toolkit using pdfresurrect and bash utilities',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Alex Mkwizu',
    author_email='alexgmkwizu@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'pdforensic': ['../bin/*'],
    },
    data_files=[
        ('bin', ['bin/mac_pdfresurrect', 'bin/linux_pdfresurrect', 'bin/pdfresurrect.1']),
    ],
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
    cmdclass={
        'install': CustomInstallCommand,
    },
)
