#!/usr/bin/env python3
"""
Fix alerts.py async/sync database session issues
"""

import re

def fix_alerts_file():
    file_path = 'src/api/routes/alerts.py'
    
    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace AsyncSession with Session
    content = content.replace('AsyncSession = Depends(get_async_db)', 'Session = Depends(get_db)')
    content = content.replace('get_async_db', 'get_db')
    
    # Replace async await patterns with sync patterns
    content = re.sub(r'await db\.execute\(', 'db.execute(', content)
    content = re.sub(r'await db\.commit\(\)', 'db.commit()', content)
    content = re.sub(r'result = await db\.execute\(', 'result = db.execute(', content)
    
    # Remove async from function definitions
    content = re.sub(r'^async def (.*?):', r'def \1:', content, flags=re.MULTILINE)
    
    # Write the fixed content back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f'Fixed {file_path}')

if __name__ == '__main__':
    fix_alerts_file()