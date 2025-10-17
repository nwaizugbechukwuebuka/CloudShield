-- Initialize CloudShield database

-- Create database if it doesn't exist (PostgreSQL specific)
-- SELECT 'CREATE DATABASE cloudshield' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cloudshield');

-- Extensions for PostgreSQL
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create custom types
DO $$ BEGIN
    CREATE TYPE risk_level AS ENUM ('low', 'medium', 'high', 'critical');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE finding_type AS ENUM (
        'misconfiguration', 
        'inactive_user', 
        'public_share', 
        'overprivileged_token', 
        'suspicious_activity',
        'compliance_violation'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE integration_status AS ENUM ('active', 'inactive', 'error', 'pending');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create indexes for performance
-- These will be created automatically by SQLAlchemy, but we can pre-create them

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Insert default admin user (password: admin123 - change in production!)
-- Note: This will be handled by the application initialization script
-- INSERT INTO users (email, username, hashed_password, is_active, is_superuser) 
-- VALUES ('admin@cloudshield.com', 'admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeXGthXE2/C.X.uby', true, true)
-- ON CONFLICT (email) DO NOTHING;

-- Create a function to clean up old findings (optional)
CREATE OR REPLACE FUNCTION cleanup_old_findings()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM findings 
    WHERE created_at < CURRENT_DATE - INTERVAL '90 days' 
    AND risk_level = 'low';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create a function to get risk statistics
CREATE OR REPLACE FUNCTION get_risk_statistics(user_id_param UUID DEFAULT NULL)
RETURNS TABLE (
    risk_level risk_level,
    count BIGINT
) AS $$
BEGIN
    IF user_id_param IS NOT NULL THEN
        RETURN QUERY
        SELECT f.risk_level, COUNT(*)
        FROM findings f
        JOIN integrations i ON f.integration_id = i.id
        WHERE i.user_id = user_id_param
        GROUP BY f.risk_level;
    ELSE
        RETURN QUERY
        SELECT f.risk_level, COUNT(*)
        FROM findings f
        GROUP BY f.risk_level;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions (adjust as needed for your setup)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cloudshield;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cloudshield;
-- GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO cloudshield;
