
import os
from sqlalchemy import create_engine, text

DATABASE_URL = os.environ.get('DATABASE_URL')

def migrate_database():
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as conn:
        # Add ssh_key column if it doesn't exist
        try:
            conn.execute(text("""
                ALTER TABLE vps_servers 
                ADD COLUMN IF NOT EXISTS ssh_key TEXT;
            """))
            conn.commit()
            print("✓ Database migration completed successfully")
        except Exception as e:
            print(f"Migration error: {e}")

if __name__ == "__main__":
    migrate_database()
