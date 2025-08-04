#!/usr/bin/env python3

import os
import shutil


def get_pdfresurrect_path():
    """
    Get the absolute path to the pdfresurrect binary.
    
    Returns:
        str: The absolute path to the pdfresurrect binary.
    """
    # Get the directory where this module is located
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Go up one level to the package root and then into bin
    package_root = os.path.dirname(current_dir)
    pdfresurrect_path = os.path.join(package_root, 'bin', 'pdfresurrect')
    
    # If the binary doesn't exist at the expected location, try alternative paths
    if not os.path.exists(pdfresurrect_path):
        # Try looking in the same directory as this file
        local_path = os.path.join(current_dir, '..', 'bin', 'pdfresurrect')
        local_path = os.path.abspath(local_path)
        if os.path.exists(local_path):
            pdfresurrect_path = local_path
        else:
            # Try system PATH
            system_path = shutil.which('pdfresurrect')
            if system_path:
                pdfresurrect_path = system_path
            else:
                raise FileNotFoundError(f"pdfresurrect binary not found. Searched paths: {pdfresurrect_path}, {local_path}")
    
    return pdfresurrect_path
