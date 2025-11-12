#!/usr/bin/env python3
"""
Fix scan_services.py async/sync database issues
"""

import re

def fix_scan_services():
    file_path = 'src/api/services/scan_services.py'
    
    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace async database usage patterns
    content = content.replace('get_async_db', 'get_db')
    content = re.sub(r'async with get_db\(\) as db:', 'with next(get_db()) as db:', content)
    content = re.sub(r'async with get_db\(\):', 'with next(get_db()):', content)
    
    # Write the fixed content back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f'Fixed {file_path}')

if __name__ == '__main__':
    fix_scan_services()