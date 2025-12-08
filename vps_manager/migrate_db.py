
import os
from sqlalchemy import create_engine, text

# Get database URL from environment
DATABASE_URL = os.environ.get('DATABASE_URL')

if not DATABASE_URL:
    print("ERROR: DATABASE_URL environment variable not set")
    exit(1)

print("Connecting to database...")
engine = create_engine(DATABASE_URL)

try:
    with engine.connect() as conn:
        # Check if version column exists
        result = conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='deployments' AND column_name='version'
        """))
        
        if result.fetchone() is None:
            print("Adding 'version' column to deployments table...")
            conn.execute(text("""
                ALTER TABLE deployments 
                ADD COLUMN version INTEGER DEFAULT 1
            """))
            conn.commit()
            print("✓ Added 'version' column")
        else:
            print("✓ 'version' column already exists")
        
        # Check if error_message column exists
        result = conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='deployments' AND column_name='error_message'
        """))
        
        if result.fetchone() is None:
            print("Adding 'error_message' column to deployments table...")
            conn.execute(text("""
                ALTER TABLE deployments 
                ADD COLUMN error_message TEXT
            """))
            conn.commit()
            print("✓ Added 'error_message' column")
        else:
            print("✓ 'error_message' column already exists")
        
        print("\nMigration completed successfully!")
        
except Exception as e:
    print(f"Migration failed: {str(e)}")
    exit(1)
