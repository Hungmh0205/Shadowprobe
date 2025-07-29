from sqlalchemy import Column, String, Float, DateTime, Text, create_engine, Integer
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import json

Base = declarative_base()

class ScanHistory(Base):
    __tablename__ = 'scan_history'

    scan_id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    duration = Column(Float)
    status = Column(String)
    website_id = Column(Integer, nullable=True)  # Liên kết với website

class ScanResults(Base):
    __tablename__ = 'scan_results'

    scan_id = Column(String, primary_key=True)
    results_data = Column(Text)  # JSON string of scan results
    website_id = Column(Integer, nullable=True)  # Liên kết với website

class Website(Base):
    __tablename__ = 'websites'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    address = Column(String, nullable=False)
    description = Column(Text)
    type = Column(String, nullable=False)
    added_time = Column(DateTime, default=datetime.utcnow)

class EnrichResults(Base):
    __tablename__ = 'enrich_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    subdomain = Column(String, nullable=False)
    ip_address = Column(String)
    status = Column(String)
    geo_country = Column(String)
    geo_city = Column(String)
    geo_asn = Column(String)
    geo_isp = Column(String)
    open_ports = Column(Text)  # JSON string
    technologies = Column(Text)  # JSON string
    screenshot_url = Column(String)
    screenshot_alt1 = Column(String)
    screenshot_alt2 = Column(String)
    screenshot_alt3 = Column(String)
    screenshot_alt4 = Column(String)
    whois_registrar = Column(String)
    whois_creation_date = Column(String)
    whois_expiration_date = Column(String)
    whois_status = Column(String)
    reverse_ip_domains = Column(Text)  # JSON string
    http_status = Column(String)
    https_status = Column(String)
    hash_md5 = Column(String)
    hash_sha256 = Column(String)
    security_headers = Column(Text)  # JSON string
    enrich_time = Column(DateTime, default=datetime.utcnow)
    website_id = Column(Integer, nullable=True)  # Liên kết với website

DATABASE_URL = 'sqlite:///db/history.db'
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    
    # Auto-migration: Add website_id column if not exists
    try:
        import sqlite3
        db_path = 'db/history.db'
        
        # Connect directly to SQLite for migration
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check scan_history table
        cursor.execute("PRAGMA table_info(scan_history)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'website_id' not in columns:
            print("Adding website_id column to scan_history table...")
            cursor.execute("ALTER TABLE scan_history ADD COLUMN website_id INTEGER")
            print("✓ Added website_id to scan_history")
        
        # Check scan_results table
        cursor.execute("PRAGMA table_info(scan_results)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'website_id' not in columns:
            print("Adding website_id column to scan_results table...")
            cursor.execute("ALTER TABLE scan_results ADD COLUMN website_id INTEGER")
            print("✓ Added website_id to scan_results")
        
        conn.commit()
        conn.close()
        print("✓ Database migration completed successfully!")
        
    except Exception as e:
        print(f"Migration warning: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()

def add_scan(scan_id, target, scan_type, start_time, end_time, duration, status, website_id=None):
    db = SessionLocal()
    try:
        scan = ScanHistory(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            status=status,
            website_id=website_id
        )
        db.add(scan)
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def history_scan():
    db = SessionLocal()
    history = db.query(ScanHistory).all()
    db.close()
    return history

def get_scan_by_id(scan_id):
    db = SessionLocal()
    scan = db.query(ScanHistory).filter(ScanHistory.scan_id == scan_id).first()
    db.close()
    return scan

def get_scan_by_target(target):
    db = SessionLocal()
    scan = db.query(ScanHistory).filter(ScanHistory.target == target).all()
    db.close()
    return scan

def get_scan_by_scan_type(scan_type):
    db = SessionLocal()
    scan = db.query(ScanHistory).filter(ScanHistory.scan_type == scan_type).all()
    db.close()
    return scan

def save_scan_results(scan_id, results_data, website_id=None):
    """Save scan results to database (upsert)"""
    db = SessionLocal()
    try:
        # Convert results to JSON string
        if isinstance(results_data, dict):
            results_json = json.dumps(results_data, default=str)
        else:
            results_json = json.dumps(results_data, default=str)
        scan_result = db.query(ScanResults).filter(ScanResults.scan_id == scan_id).first()
        if scan_result:
            scan_result.results_data = results_json
            scan_result.website_id = website_id
        else:
            scan_result = ScanResults(
                scan_id=scan_id,
                results_data=results_json,
                website_id=website_id
            )
            db.add(scan_result)
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def get_scan_results(scan_id):
    """Get scan results from database"""
    db = SessionLocal()
    try:
        scan_result = db.query(ScanResults).filter(ScanResults.scan_id == scan_id).first()
        if scan_result and scan_result.results_data is not None:
            return json.loads(str(scan_result.results_data))
        return None
    except Exception as e:
        return None
    finally:
        db.close()

def add_website(name, address, description, type):
    db = SessionLocal()
    try:
        website = Website(
            name=name,
            address=address,
            description=description,
            type=type
        )
        db.add(website)
        db.commit()
        db.refresh(website)
        return website
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def get_all_websites():
    db = SessionLocal()
    try:
        return db.query(Website).order_by(Website.added_time.desc()).all()
    finally:
        db.close()

def delete_website_by_id(website_id):
    db = SessionLocal()
    try:
        website = db.query(Website).filter(Website.id == website_id).first()
        if website:
            db.delete(website)
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def update_website_by_id(website_id, name, address, description, type):
    db = SessionLocal()
    try:
        website = db.query(Website).filter(Website.id == website_id).first()
        if not website:
            return None
        website.name = name
        website.address = address
        website.description = description
        website.type = type
        db.commit()
        db.refresh(website)
        return website
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def get_scans_by_website(website_id):
    """Get all scans for a specific website"""
    db = SessionLocal()
    try:
        scans = db.query(ScanHistory).filter(ScanHistory.website_id == website_id).order_by(ScanHistory.start_time.desc()).all()
        return scans
    finally:
        db.close()

def get_latest_scan_by_website(website_id):
    """Get the latest scan for a specific website"""
    db = SessionLocal()
    try:
        scan = db.query(ScanHistory).filter(ScanHistory.website_id == website_id).order_by(ScanHistory.start_time.desc()).first()
        return scan
    finally:
        db.close()

def get_scan_comparison(website_id, limit=2):
    """Get latest scans for comparison (for detecting changes)"""
    db = SessionLocal()
    try:
        scans = db.query(ScanHistory).filter(ScanHistory.website_id == website_id).order_by(ScanHistory.start_time.desc()).limit(limit).all()
        return scans
    finally:
        db.close()

def save_enrich_result(enrich_data, website_id=None):
    """Save enrich result to database"""
    db = SessionLocal()
    try:
        # Safely extract and convert data
        def safe_str(value):
            if value is None:
                return ''
            return str(value)
        
        def safe_json(value):
            if value is None:
                return '[]'
            try:
                return json.dumps(value)
            except:
                return '[]'
        
        # Extract data from enrich result with safe conversion
        enrich_result = EnrichResults(
            subdomain=safe_str(enrich_data.get('subdomain', '')),
            ip_address=safe_str(enrich_data.get('ip', '')),
            status=safe_str(enrich_data.get('status', '')),
            geo_country=safe_str(enrich_data.get('geo', {}).get('country', '')),
            geo_city=safe_str(enrich_data.get('geo', {}).get('city', '')),
            geo_asn=safe_str(enrich_data.get('geo', {}).get('asn', '')),
            geo_isp=safe_str(enrich_data.get('geo', {}).get('isp', '')),
            open_ports=safe_json(enrich_data.get('ports', [])),
            technologies=safe_json(enrich_data.get('technologies', [])),
            screenshot_url=safe_str(enrich_data.get('screenshot_url', '')),
            screenshot_alt1=safe_str(enrich_data.get('screenshot_alt1', '')),
            screenshot_alt2=safe_str(enrich_data.get('screenshot_alt2', '')),
            screenshot_alt3=safe_str(enrich_data.get('screenshot_alt3', '')),
            screenshot_alt4=safe_str(enrich_data.get('screenshot_alt4', '')),
            whois_registrar=safe_str(enrich_data.get('whois', {}).get('registrar', '')),
            whois_creation_date=safe_str(enrich_data.get('whois', {}).get('creation_date', '')),
            whois_expiration_date=safe_str(enrich_data.get('whois', {}).get('expiration_date', '')),
            whois_status=safe_str(enrich_data.get('whois', {}).get('status', '')),
            reverse_ip_domains=safe_json(enrich_data.get('reverse_ip_domains', [])),
            http_status=safe_str(enrich_data.get('http', {}).get('status', '')),
            https_status=safe_str(enrich_data.get('https', {}).get('status', '')),
            hash_md5=safe_str(enrich_data.get('hash', {}).get('md5', '')),
            hash_sha256=safe_str(enrich_data.get('hash', {}).get('sha256', '')),
            security_headers=safe_json(enrich_data.get('security_headers', {})),
            website_id=website_id
        )
        
        db.add(enrich_result)
        db.commit()
        
        return enrich_result.id
        
    except Exception as e:
        db.rollback()
        print(f"Database error: {e}")
        raise e
    finally:
        db.close()

def get_enrich_results_by_subdomain(subdomain, limit=10):
    """Get enrich results for a specific subdomain"""
    db = SessionLocal()
    try:
        results = db.query(EnrichResults).filter(
            EnrichResults.subdomain == subdomain
        ).order_by(EnrichResults.enrich_time.desc()).limit(limit).all()
        return results
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def get_enrich_results_by_website(website_id, limit=50):
    """Get enrich results for a specific website"""
    db = SessionLocal()
    try:
        results = db.query(EnrichResults).filter(
            EnrichResults.website_id == website_id
        ).order_by(EnrichResults.enrich_time.desc()).limit(limit).all()
        return results
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def get_latest_enrich_result(subdomain):
    """Get the latest enrich result for a subdomain"""
    db = SessionLocal()
    try:
        result = db.query(EnrichResults).filter(
            EnrichResults.subdomain == subdomain
        ).order_by(EnrichResults.enrich_time.desc()).first()
        return result
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def delete_enrich_result(result_id):
    """Delete an enrich result by ID"""
    db = SessionLocal()
    try:
        result = db.query(EnrichResults).filter(EnrichResults.id == result_id).first()
        if result:
            db.delete(result)
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


