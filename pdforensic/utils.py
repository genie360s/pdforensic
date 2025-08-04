#!/usr/bin/env python3

import os
import shutil
import platform
import stat


def get_pdfresurrect_path():
    """
    Get the absolute path to the pdfresurrect binary based on the operating system.
    
    Returns:
        str: The absolute path to the pdfresurrect binary.
    """
    # Determine the correct binary name based on the operating system
    system = platform.system().lower()
    if system == 'darwin':  # macOS
        binary_name = 'mac_pdfresurrect'
    elif system == 'linux':
        binary_name = 'linux_pdfresurrect'
    else:
        # Fallback to generic name for other systems
        binary_name = 'linux_pdfresurrect'
    
    # Get the directory where this module is located
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Go up one level to the package root and then into bin
    package_root = os.path.dirname(current_dir)
    pdfresurrect_path = os.path.join(package_root, 'bin', binary_name)
    
    # If the binary doesn't exist at the expected location, try alternative paths
    if not os.path.exists(pdfresurrect_path):
        # Try looking in the same directory as this file
        local_path = os.path.join(current_dir, '..', 'bin', binary_name)
        local_path = os.path.abspath(local_path)
        if os.path.exists(local_path):
            pdfresurrect_path = local_path
        else:
            # Try system PATH with generic name
            system_path = shutil.which('pdfresurrect')
            if system_path:
                pdfresurrect_path = system_path
            else:
                raise FileNotFoundError(f"pdfresurrect binary not found. Searched paths: {pdfresurrect_path}, {local_path}")
    
    # Ensure the binary has executable permissions
    _ensure_executable(pdfresurrect_path)
    
    return pdfresurrect_path


def _ensure_executable(file_path):
    """
    Ensure the given file has executable permissions.
    
    Args:
        file_path (str): Path to the file to make executable.
    """
    try:
        if os.path.exists(file_path):
            # Get current permissions
            current_permissions = os.stat(file_path).st_mode
            # Add execute permissions for owner, group, and others
            new_permissions = current_permissions | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            os.chmod(file_path, new_permissions)
    except Exception as e:
        print(f"Warning: Could not set executable permissions for {file_path}: {e}")
