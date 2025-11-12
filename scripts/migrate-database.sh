#!/bin/bash
# Database migration script for CloudShield

set -e

echo "🗄️  Running database migrations for CloudShield"

# Set environment variables
export PYTHONPATH=/app

# Check if database is accessible
echo "Checking database connectivity..."
python -c "
from src.api.database import engine
try:
    with engine.connect() as conn:
        print('✅ Database connection successful')
except Exception as e:
    print(f'❌ Database connection failed: {e}')
    exit(1)
"

# Run Alembic migrations
echo "Running Alembic migrations..."
alembic upgrade head

echo "✅ Database migrations completed successfully!"

# Optional: Run data seeding for initial deployment
if [ "$RUN_SEED" == "true" ]; then
    echo "Running database seeding..."
    python scripts/seed_database.py
    echo "✅ Database seeding completed!"
fi
