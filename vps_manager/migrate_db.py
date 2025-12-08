
import os
from sqlalchemy import create_engine, text

DATABASE_URL = os.environ.get('DATABASE_URL')

def migrate_database():
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as conn:
        # Add missing columns if they don't exist
        try:
            conn.execute(text("""
                ALTER TABLE vps_servers 
                ADD COLUMN IF NOT EXISTS ssh_key TEXT;
            """))
            conn.execute(text("""
                ALTER TABLE vps_servers 
                ADD COLUMN IF NOT EXISTS "group" VARCHAR(50) DEFAULT 'default';
            """))
            conn.execute(text("""
                ALTER TABLE vps_servers 
                ADD COLUMN IF NOT EXISTS tags VARCHAR(255) DEFAULT '';
            """))
            conn.execute(text("""
                ALTER TABLE vps_servers 
                ADD COLUMN IF NOT EXISTS cpu_usage FLOAT DEFAULT 0.0;
            """))
            conn.execute(text("""
                ALTER TABLE vps_servers 
                ADD COLUMN IF NOT EXISTS ram_usage FLOAT DEFAULT 0.0;
            """))
            conn.execute(text("""
                ALTER TABLE vps_servers 
                ADD COLUMN IF NOT EXISTS disk_usage FLOAT DEFAULT 0.0;
            """))
            conn.commit()
            print("✓ Database migration completed successfully")
        except Exception as e:
            print(f"Migration error: {e}")

if __name__ == "__main__":
    migrate_database()
