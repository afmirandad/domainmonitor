
import pymysql
pymysql.install_as_MySQLdb()
from sqlalchemy import create_engine, MetaData, text
from app.config.settings import MYSQL_URL, logger


engine = create_engine(MYSQL_URL)
metadata = MetaData()

def ensure_database_schema():
	"""Ensure the database schema is up to date with all required columns"""
	logger.info("🔧 Checking and updating database schema...")
	# Always try to create the table first
	metadata.create_all(engine)
	try:
		with engine.connect() as conn:
			# Check if new columns exist and add them if they don't
			columns_to_add = [
				('ip_address', 'VARCHAR(45)'),
				('is_active', 'VARCHAR(10)'),
				('open_ports', 'TEXT'),
				('services', 'TEXT'),
				('last_scanned', 'DATETIME')
			]
			for column_name, column_type in columns_to_add:
				try:
					# Try to add the column
					alter_sql = f"ALTER TABLE subdomains ADD COLUMN {column_name} {column_type}"
					conn.execute(text(alter_sql))
					conn.commit()
					logger.info(f"✅ Added column: {column_name}")
				except Exception as e:
					if "Duplicate column name" in str(e) or "already exists" in str(e):
						logger.info(f"ℹ️ Column {column_name} already exists")
					elif "doesn't exist" in str(e) or "does not exist" in str(e):
						logger.warning(f"⚠️ Table does not exist when adding column {column_name}, skipping column addition.")
					else:
						logger.warning(f"⚠️ Could not add column {column_name}: {e}")
			logger.info("✅ Database schema check completed")
	except Exception as e:
		logger.error(f"❌ Database schema update failed: {e}")

__all__ = ["engine", "metadata"]
