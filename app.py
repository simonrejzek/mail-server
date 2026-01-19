import json
import os
import random
import requests
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import atexit
from functools import wraps

from flask import Flask, jsonify, render_template, request
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from flask_limiter import Limiter # Added
from flask_limiter.util import get_remote_address # Added

load_dotenv()

APP_ROOT = Path(__file__).resolve().parent
app = Flask(__name__, template_folder=str(APP_ROOT / 'templates'))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = app.logger

# --- Rate Limiting Setup ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[os.getenv("RATE_LIMIT_DEFAULT", "60 per minute")], 
    storage_uri="memory://",  
    strategy="fixed-window"
)

# --- Authentication Decorator ---
def require_api_password(f):
    """Decorator to require API password via Bearer token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_password = os.getenv('API_PASSWORD')
        
        # If no API_PASSWORD is set, allow access (for backward compatibility)
        if not api_password:
            logger.warning("API_PASSWORD not set - endpoint is unprotected!")
            return f(*args, **kwargs)
        
        # Check Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning(f"Unauthorized access attempt from {request.remote_addr} - Missing Bearer token")
            return jsonify({'error': 'Unauthorized - Missing Bearer token'}), 401
        
        provided_token = auth_header.replace('Bearer ', '')
        if provided_token != api_password:
            logger.warning(f"Unauthorized access attempt from {request.remote_addr} - Invalid token")
            return jsonify({'error': 'Unauthorized - Invalid token'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def _extract_portal_password():
    """Fetch portal password from headers, auth header, JSON, or query params."""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.lower().startswith('portal '):
        return auth_header.split(' ', 1)[1].strip()
    header_password = request.headers.get('X-Portal-Password')
    if header_password: return header_password
    request_json = request.get_json(silent=True)
    if request_json:
        for key in ('password', 'portal_password', 'portalPassword'):
            if key in request_json: return request_json.get(key)
    return request.args.get('password')

def require_portal_password(f):
    """Lightweight password gate for the portal endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        provided = _extract_portal_password()
        if not provided:
            logger.warning(f"Portal access attempt without password from {request.remote_addr}")
            return jsonify({'error': 'Unauthorized - Missing portal password'}), 401
        if provided != PORTAL_PASSWORD:
            logger.warning(f"Portal access denied for {request.remote_addr} - Invalid password")
            return jsonify({'error': 'Unauthorized - Invalid portal password'}), 403
        return f(*args, **kwargs)
    return decorated

# Use local directory instead of Docker /app path
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'emails.db')
PORTAL_PASSWORD = os.getenv('PORTAL_PASSWORD', 'disctools.store')

WORDS = [
    "apple", "banana", "cherry", "date", "elderberry", "fig", "grape", "honeydew",
    "kiwi", "lemon", "mango", "nectarine", "orange", "papaya", "quince", "raspberry",
    "strawberry", "tangerine", "ugli", "vanilla", "watermelon", "xigua", "yam", "zucchini",
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
    "india", "juliett", "kilo", "lima", "mike", "november", "oscar", "papa",
    "quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "xray",
    "yankee", "zulu", "red", "blue", "green", "yellow", "purple", "silver", "gold"
]

RULE_NAME_PREFIX = "temp_email_api:"
LOCAL_PART_REGEX = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$')

# Custom Exception for expiry errors
class InvalidExpiryError(ValueError):
    pass

# --- Database Setup ---
def init_db():
    try:
        db_path_obj = Path(DATABASE_PATH)
        db_path_obj.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS temporary_emails (
                email TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_expires_at ON temporary_emails (expires_at)
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS received_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                to_email TEXT NOT NULL,
                from_email TEXT,
                subject TEXT,
                html TEXT,
                text TEXT,
                received_at TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_to_email ON received_emails (to_email)
        ''')
        conn.commit()
        conn.close()
        logger.info(f"Database initialized successfully at internal path {DATABASE_PATH}")
    except Exception as e:
        logger.exception(f"CRITICAL: Failed to initialize database at {DATABASE_PATH}: {e}")
        raise


# --- Helper Functions ---
def parse_expiry(expiry_str):
    """
    Parses expiry string (e.g., '1h', '3d', '30m') into a future datetime object.
    Raises InvalidExpiryError if format is wrong or duration is too short (min 10m).
    Returns None if no expiry_str is provided.
    """
    MINIMUM_EXPIRY_MINUTES = 10 # Keep minimum check here or make it env var too
    if not expiry_str: return None
    match = re.match(r'^(\d+)([hdm])$', expiry_str.lower())
    if not match:
        raise InvalidExpiryError(f"Invalid expiry format: '{expiry_str}'. Use format like '10m', '1h', '2d'.")
    value, unit = match.groups(); value = int(value)
    now = datetime.now(timezone.utc)
    if unit == 'h': delta = timedelta(hours=value)
    elif unit == 'd': delta = timedelta(days=value)
    elif unit == 'm': delta = timedelta(minutes=value)
    else: raise InvalidExpiryError("Internal error parsing expiry unit.")
    min_delta = timedelta(minutes=MINIMUM_EXPIRY_MINUTES)
    if delta < min_delta:
        raise InvalidExpiryError(f"Minimum expiry duration is {MINIMUM_EXPIRY_MINUTES} minutes. Requested: '{expiry_str}'")
    return now + delta

def normalize_local_part(custom_local_part, domain_name):
    """Validate and normalize a custom local-part for the configured domain."""
    if not custom_local_part or not str(custom_local_part).strip():
        return None, "Custom email cannot be empty."
    local_part = str(custom_local_part).strip().lower()
    if '@' in local_part:
        requested_local, requested_domain = local_part.split('@', 1)
        if requested_domain.lower() != domain_name.lower():
            return None, f"Custom email must use the configured domain ({domain_name})."
        local_part = requested_local
    if not LOCAL_PART_REGEX.match(local_part):
        return None, "Custom email can only use letters, numbers, dots, hyphens, and underscores (1-64 chars)."
    return local_part, None

def build_temp_email(local_part=None, domain_name=None):
    """Return a fully qualified email for the configured domain (random or custom)."""
    domain_name = domain_name or os.getenv('DOMAIN_NAME')
    if not domain_name:
        return None, "Missing DOMAIN_NAME environment variable."
    if local_part:
        normalized_local, error = normalize_local_part(local_part, domain_name)
        if error:
            return None, error
        return f"{normalized_local}@{domain_name}", None
    random_prefix = generate_random_prefix()
    return f"{random_prefix}@{domain_name}", None

def add_email_to_db(email, expires_at):
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        created_at = datetime.now(timezone.utc).isoformat()
        expires_at_iso = expires_at.isoformat() if expires_at else 'never'
        cursor.execute('''
            INSERT OR REPLACE INTO temporary_emails (email, created_at, expires_at)
            VALUES (?, ?, ?)
        ''', (email, created_at, expires_at_iso))
        conn.commit()
        logger.info(f"Added/updated email {email} in DB with expiry {expires_at_iso}")
        return True
    except Exception as e:
        logger.exception(f"Failed to add email {email} to database: {e}")
        if conn: conn.rollback()
        return False
    finally:
        if conn: conn.close()

def remove_email_from_db(email):
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM temporary_emails WHERE email = ?', (email,))
        deleted_rows = cursor.rowcount
        conn.commit()
        if deleted_rows > 0: logger.info(f"Removed email {email} from DB.")
        else: logger.warning(f"Attempted to remove {email} from DB, but it was not found.")
        return True
    except Exception as e:
        logger.exception(f"Failed to remove email {email} from database: {e}")
        if conn: conn.rollback()
        return False
    finally:
        if conn: conn.close()

def generate_random_prefix():
    word1 = random.choice(WORDS); word2 = random.choice(WORDS)
    random_digits = random.randint(100, 999)
    return f"{word1}_{word2}{random_digits}"

def create_cloudflare_route(api_token, zone_id, temp_email, destination_email):
    api_endpoint = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules"
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    rule_name = f"{RULE_NAME_PREFIX} {temp_email}"
    payload = {"actions": [{"type": "forward", "value": [destination_email]}], "matchers": [{"field": "to", "type": "literal", "value": temp_email}], "enabled": True, "name": rule_name, "priority": 50}
    try:
        logger.info(f"Attempting to create Cloudflare route for {temp_email} with name '{rule_name}'")
        response = requests.post(api_endpoint, headers=headers, json=payload)
        if response.status_code == 403:
             logger.error(f"Cloudflare API Error 403: Check permissions. Response: {response.text}")
             return False, f"Permission denied. Check API Token. Details: {response.text}"
        if response.status_code == 400:
            resp_text = response.text.lower()
            if "rule with the same name already exists" in resp_text:
                 logger.warning(f"Cloudflare API Error 400: Duplicate rule name '{rule_name}'.")
                 return False, f"A rule with the name '{rule_name}' may already exist."
            elif "rule with the same matcher already exists" in resp_text:
                 logger.warning(f"Cloudflare API Error 400: Duplicate matcher for email '{temp_email}'.")
                 return False, f"A rule matching email '{temp_email}' may already exist."
        response.raise_for_status()
        response_data = response.json()
        logger.info(f"Cloudflare API response: {response_data}")
        if response_data.get("success"):
            logger.info(f"Successfully created routing rule for {temp_email}")
            return True, None
        else:
            error_detail = response_data.get('errors', [{'message': 'Unknown Cloudflare API error'}])
            logger.error(f"Cloudflare API indicated failure: {error_detail}")
            return False, error_detail
    except requests.exceptions.RequestException as e:
        error_body = "Could not decode error response.";
        if hasattr(e, 'response') and e.response is not None:
            try: error_body = e.response.text
            except Exception: pass
        logger.error(f"Error calling Cloudflare API: {e}. Response: {error_body}")
        return False, f"Network or API error: {e}"
    except Exception as e:
        logger.exception(f"An unexpected error occurred during Cloudflare API call for {temp_email}")
        return False, f"Unexpected server error: {e}"

def get_all_cloudflare_rules(api_token, zone_id):
    all_rules = []; page = 1
    api_endpoint = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules"
    headers = {"Authorization": f"Bearer {api_token}"}
    while True:
        params = {'page': page, 'per_page': 50}
        try:
            logger.debug(f"Fetching page {page} of Cloudflare email rules")
            response = requests.get(api_endpoint, headers=headers, params=params)
            response.raise_for_status(); response_data = response.json()
            if not response_data.get("success"):
                error_detail = response_data.get('errors', 'Unknown Cloudflare API error listing rules')
                logger.error(f"Cloudflare API failed on list (page {page}): {error_detail}")
                return None, error_detail
            rules_on_page = response_data.get("result", [])
            if not rules_on_page: break
            all_rules.extend(rules_on_page)
            result_info = response_data.get("result_info", {})
            total_pages = result_info.get("total_pages", 1)
            if page >= total_pages: break
            page += 1
        except requests.exceptions.RequestException as e:
            error_body = "Could not decode list response."
            if hasattr(e, 'response') and e.response is not None:
                try: error_body = e.response.text
                except Exception: pass
            logger.error(f"Error listing Cloudflare rules (page {page}): {e}. Response: {error_body}")
            return None, f"Network or API error during list: {e}"
        except Exception as e:
            logger.exception(f"Unexpected error listing Cloudflare rules (page {page})")
            return None, f"Unexpected server error during list: {e}"
    logger.info(f"Successfully fetched {len(all_rules)} total rules from Cloudflare.")
    return all_rules, None

def delete_cloudflare_rule(api_token, zone_id, rule_id):
    delete_endpoint = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules/{rule_id}"
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        logger.info(f"Attempting to delete Cloudflare rule ID {rule_id}")
        response = requests.delete(delete_endpoint, headers=headers)
        if response.status_code == 404:
             logger.warning(f"Cloudflare rule ID {rule_id} not found for deletion.")
             return True, None
        response.raise_for_status()
        response_data = response.json()
        logger.debug(f"Cloudflare DELETE API response: {response_data}")
        if response_data.get("success"):
            logger.info(f"Successfully deleted Cloudflare rule ID {rule_id}")
            return True, None
        else:
            error_detail = response_data.get('errors', [{'message': 'Unknown error during deletion'}])
            logger.error(f"Cloudflare API indicated failure during delete for {rule_id}: {error_detail}")
            return False, error_detail
    except requests.exceptions.RequestException as e:
        error_body = "Could not decode delete response."
        if hasattr(e, 'response') and e.response is not None:
            try: error_body = e.response.text
            except Exception: pass
        logger.error(f"Error deleting Cloudflare rule {rule_id}: {e}. Response: {error_body}")
        return False, f"Network or API error during delete: {e}"
    except Exception as e:
        logger.exception(f"Unexpected error deleting Cloudflare rule {rule_id}")
        return False, f"Unexpected server error during delete: {e}"


def provision_temp_email(local_part=None, expiry_str=None):
    """Create a temp email (random or custom), Cloudflare rule, and store expiry."""
    api_token = os.getenv('CLOUDFLARE_API_TOKEN')
    zone_id = os.getenv('CLOUDFLARE_ZONE_ID')
    destination_email = os.getenv('DESTINATION_EMAIL')
    domain_name = os.getenv('DOMAIN_NAME')
    missing_vars = []
    if not api_token: missing_vars.append('CLOUDFLARE_API_TOKEN')
    if not zone_id: missing_vars.append('CLOUDFLARE_ZONE_ID')
    if not destination_email: missing_vars.append('DESTINATION_EMAIL')
    if not domain_name: missing_vars.append('DOMAIN_NAME')
    if missing_vars:
        error_message = f"Missing required environment variables: {', '.join(missing_vars)}"
        logger.error(error_message)
        return None, 500, error_message

    try:
        expires_at = parse_expiry(expiry_str)
    except InvalidExpiryError as e:
        logger.warning(f"Invalid expiry requested: {e}")
        return None, 400, str(e)
    except Exception as e:
        logger.exception("Error during email generation/expiry parsing")
        return None, 500, f"Failed to generate email or parse expiry: {e}"

    temp_email, email_error = build_temp_email(local_part, domain_name)
    if email_error:
        logger.warning(f"Invalid email request: {email_error}")
        return None, 400, email_error

    logger.info(f"Provisioning temporary email {temp_email}, expiry {expires_at or 'never'}")
    cf_success, cf_error_details = create_cloudflare_route(api_token, zone_id, temp_email, destination_email)
    if cf_success:
        db_success = add_email_to_db(temp_email, expires_at)
        if not db_success:
            logger.error(f"Failed to add {temp_email} to database after Cloudflare success!")
        return {'email': temp_email, 'expires_at': expires_at.isoformat() if expires_at else None}, 200
    logger.error(f"Failed to create Cloudflare routing rule for {temp_email}: {cf_error_details}")
    return None, 500, f"Failed to create Cloudflare routing rule: {cf_error_details}"

def remove_email_rule(email_to_remove):
    """Shared removal routine for API and portal."""
    api_token = os.getenv('CLOUDFLARE_API_TOKEN')
    zone_id = os.getenv('CLOUDFLARE_ZONE_ID')
    if not api_token or not zone_id:
        return {'error': 'Missing CLOUDFLARE_API_TOKEN or CLOUDFLARE_ZONE_ID environment variables'}, 500

    all_rules, list_error = get_all_cloudflare_rules(api_token, zone_id)
    if list_error:
        return {'error': 'Failed to retrieve rules to find rule ID', 'details': list_error}, 500

    rule_id_to_remove = None
    for rule in all_rules:
        matchers = rule.get("matchers", [])
        for matcher in matchers:
            if (matcher.get("field") == "to" and matcher.get("type") == "literal" and matcher.get("value") == email_to_remove):
                rule_id_to_remove = rule.get("id")
                logger.info(f"Found rule ID {rule_id_to_remove} for email {email_to_remove}")
                break
        if rule_id_to_remove: break

    if not rule_id_to_remove:
        logger.warning(f"Rule for email {email_to_remove} not found in Cloudflare.")
        remove_email_from_db(email_to_remove)
        return {'error': f'Rule for email {email_to_remove} not found'}, 404

    cf_delete_success, cf_delete_error = delete_cloudflare_rule(api_token, zone_id, rule_id_to_remove)
    if cf_delete_success:
        db_remove_success = remove_email_from_db(email_to_remove)
        if not db_remove_success:
            logger.error(f"Deleted Cloudflare rule for {email_to_remove}, but failed to remove from local DB.")
        return {'message': f'Successfully removed rule for {email_to_remove}'}, 200
    return {'error': 'Cloudflare failed to delete the rule', 'details': cf_delete_error}, 500

# --- Scheduled Job ---
def cleanup_expired_emails():
    with app.app_context():
        logger.info("Running scheduled cleanup job for expired emails...")
        api_token = os.getenv('CLOUDFLARE_API_TOKEN')
        zone_id = os.getenv('CLOUDFLARE_ZONE_ID')
        if not api_token or not zone_id:
            logger.error("Cleanup job: Missing Cloudflare credentials.")
            return
        conn = None
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            now_iso = datetime.now(timezone.utc).isoformat()
            cursor.execute("SELECT email FROM temporary_emails WHERE expires_at != 'never' AND expires_at < ?", (now_iso,))
            expired_emails = [row[0] for row in cursor.fetchall()]
            if not expired_emails:
                logger.info("Cleanup job: No expired emails found."); conn.close(); return
            logger.info(f"Cleanup job: Found {len(expired_emails)} expired emails: {expired_emails}")
            all_rules, list_error = get_all_cloudflare_rules(api_token, zone_id)
            if list_error:
                logger.error(f"Cleanup job: Failed list rules for deletion: {list_error}"); conn.close(); return
            emails_to_delete_from_db = []
            for email in expired_emails:
                rule_id_to_remove = None
                for rule in all_rules:
                    matchers = rule.get("matchers", [])
                    for matcher in matchers:
                         if (matcher.get("field") == "to" and matcher.get("type") == "literal" and matcher.get("value") == email):
                             rule_id_to_remove = rule.get("id"); break
                    if rule_id_to_remove: break
                if rule_id_to_remove:
                    logger.info(f"Cleanup job: Found rule ID {rule_id_to_remove} for expired email {email}. Deleting.")
                    success, delete_error = delete_cloudflare_rule(api_token, zone_id, rule_id_to_remove)
                    if success:
                        logger.info(f"Cleanup job: Deleted Cloudflare rule for expired email {email}.")
                        emails_to_delete_from_db.append(email)
                    else: logger.error(f"Cleanup job: Failed Cloudflare deletion for {email}. Error: {delete_error}")
                else:
                    logger.warning(f"Cleanup job: Cloudflare rule for expired email {email} not found. Removing from DB.")
                    emails_to_delete_from_db.append(email)
            if emails_to_delete_from_db:
                placeholders = ','.join('?' * len(emails_to_delete_from_db))
                cursor.execute(f"DELETE FROM temporary_emails WHERE email IN ({placeholders})", emails_to_delete_from_db)
                conn.commit()
                logger.info(f"Cleanup job: Removed {len(emails_to_delete_from_db)} entries from DB.")
            conn.close()
            logger.info("Cleanup job finished.")
        except Exception as e:
            logger.exception("Cleanup job: Error during cleanup.")
            if conn: conn.rollback(); conn.close()


# --- Flask Routes ---

# get rate limit strings from env var, provide defaults if empty
generate_rate_limit = os.getenv("RATE_LIMIT_GENERATE", "20 per day")
default_rate_limit = os.getenv("RATE_LIMIT_DEFAULT", "60 per minute")

@app.route('/')
@app.route('/portal')
def portal_home():
    domain_name = os.getenv('DOMAIN_NAME', 'disctools.store')
    return render_template('portal.html', domain_name=domain_name, portal_password=PORTAL_PASSWORD)

@app.route('/portal/api/generate', methods=['POST'])
@limiter.limit(generate_rate_limit)
@require_portal_password
def portal_generate_email():
    payload = request.get_json(silent=True) or {}
    custom_local = payload.get('local_part') or payload.get('localPart') or payload.get('custom_local') or request.args.get('local_part')
    expiry_str = payload.get('expiry') or request.args.get('expiry')
    use_random = payload.get('mode') == 'random' or payload.get('random') is True
    if use_random or (custom_local is not None and not str(custom_local).strip()):
        custom_local = None
    result, status_code, message = provision_temp_email(local_part=custom_local, expiry_str=expiry_str)
    if result:
        return jsonify(result), status_code
    return jsonify({'error': message}), status_code

@app.route('/portal/api/addresses', methods=['GET'])
@limiter.limit(default_rate_limit)
@require_portal_password
def portal_list_addresses():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT email, created_at, expires_at
            FROM temporary_emails
            ORDER BY datetime(created_at) DESC
        ''')
        rows = cursor.fetchall()
        addresses = []
        for email, created_at, expires_at in rows:
            addresses.append({
                'email': email,
                'created_at': created_at,
                'expires_at': None if expires_at == 'never' else expires_at
            })
        return jsonify({'addresses': addresses}), 200
    except Exception as e:
        logger.exception("Error fetching portal address list")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/portal/api/addresses/<path:email_to_remove>', methods=['DELETE'])
@limiter.limit(default_rate_limit)
@require_portal_password
def portal_remove_address(email_to_remove):
    response_body, status_code = remove_email_rule(email_to_remove)
    return jsonify(response_body), status_code

@app.route('/portal/api/inbox', methods=['GET'])
@limiter.limit(default_rate_limit)
@require_portal_password
def portal_inbox():
    email_filter = request.args.get('email') or request.args.get('to')
    limit_param = request.args.get('limit', 50)
    try:
        limit_value = int(limit_param)
        if limit_value < 1: limit_value = 1
        if limit_value > 200: limit_value = 200
    except (TypeError, ValueError):
        limit_value = 50

    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        if email_filter:
            cursor.execute('''
                SELECT id, to_email, from_email, subject, html, text, received_at
                FROM received_emails
                WHERE to_email = ?
                ORDER BY received_at DESC
                LIMIT ?
            ''', (email_filter, limit_value))
        else:
            cursor.execute('''
                SELECT id, to_email, from_email, subject, html, text, received_at
                FROM received_emails
                ORDER BY received_at DESC
                LIMIT ?
            ''', (limit_value,))
        rows = cursor.fetchall()
        emails = []
        for row in rows:
            emails.append({
                'id': row[0],
                'to': row[1],
                'from': row[2],
                'subject': row[3],
                'html': row[4],
                'text': row[5],
                'received_at': row[6]
            })
        return jsonify({'emails': emails, 'count': len(emails)}), 200
    except Exception as e:
        logger.exception("Error fetching portal inbox")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/generate', methods=['GET'])
@limiter.limit(generate_rate_limit)
@require_api_password
def generate_email_route():
    logger.info(f"Received request on /generate from {request.remote_addr}")
    expiry_str = request.args.get('expiry')
    result, status_code, message = provision_temp_email(expiry_str=expiry_str)
    if result:
        return jsonify(result), status_code
    return jsonify({'error': message}), status_code

@app.route('/list', methods=['GET'])
@limiter.limit(default_rate_limit)
@require_api_password
def list_email_routes():
    logger.info(f"Received request on /list from {request.remote_addr}")
    api_token = os.getenv('CLOUDFLARE_API_TOKEN')
    zone_id = os.getenv('CLOUDFLARE_ZONE_ID')
    if not api_token or not zone_id:
        return jsonify({'error': 'Missing CLOUDFLARE_API_TOKEN or CLOUDFLARE_ZONE_ID environment variables'}), 500
    all_rules, error = get_all_cloudflare_rules(api_token, zone_id)
    if error:
        return jsonify({'error': 'Failed to retrieve rules from Cloudflare', 'details': error}), 500
    generated_emails = []
    for rule in all_rules:
        rule_name = rule.get("name", "")
        if rule_name.startswith(RULE_NAME_PREFIX):
            matchers = rule.get("matchers", [])
            for matcher in matchers:
                if matcher.get("field") == "to" and matcher.get("type") == "literal":
                    email = matcher.get("value")
                    if email: generated_emails.append(email)
                    break
    logger.info(f"Found {len(generated_emails)} email rules matching prefix '{RULE_NAME_PREFIX}'")
    return jsonify({'generated_emails': generated_emails}), 200

@app.route('/remove/<path:email_to_remove>', methods=['DELETE'])
@limiter.limit(default_rate_limit)
@require_api_password
def remove_email_route(email_to_remove):
    logger.info(f"Received request on /remove for {email_to_remove} from {request.remote_addr}")
    response_body, status_code = remove_email_rule(email_to_remove)
    return jsonify(response_body), status_code


@app.route('/webhook/inbound', methods=['POST'])
@require_api_password
def inbound_email_webhook():
    """
    Webhook endpoint for receiving inbound emails from Cloudflare Email Workers
    Cloudflare Email Workers can forward received emails here as JSON
    """
    logger.info(f"Received inbound email webhook from {request.remote_addr}")
    try:
        email_data = request.get_json()
        
        to_email = email_data.get('to', '')
        from_email = email_data.get('from', '')
        subject = email_data.get('subject', '')
        html = email_data.get('html', '')
        text = email_data.get('text', '')
        
        # Store email in database
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        received_at = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO received_emails (to_email, from_email, subject, html, text, received_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (to_email, from_email, subject, html, text, received_at))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Stored inbound email to {to_email} from {from_email}")
        return jsonify({'success': True, 'message': 'Email received'}), 200
        
    except Exception as e:
        logger.exception(f"Error processing inbound email webhook: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/emails/<email_address>', methods=['GET'])
@limiter.limit(default_rate_limit)
@require_api_password
def get_emails(email_address):
    """
    Get all received emails for a specific email address
    Returns same format as pixiboost.fun API
    Requires Bearer token authentication
    """
    logger.info(f"Fetching emails for {email_address}")
    
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, from_email, subject, html, text, received_at
            FROM received_emails
            WHERE to_email = ?
            ORDER BY received_at DESC
        ''', (email_address,))
        
        rows = cursor.fetchall()
        conn.close()
        
        emails = []
        for row in rows:
            emails.append({
                'id': row[0],
                'from': row[1],
                'subject': row[2],
                'html': row[3],
                'text': row[4],
                'received_at': row[5]
            })
        
        logger.info(f"Found {len(emails)} emails for {email_address}")
        return jsonify(emails), 200
        
    except Exception as e:
        logger.exception(f"Error fetching emails for {email_address}: {e}")
        if conn: conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
@limiter.limit(default_rate_limit)
def health_check():
    """Enhanced health check endpoint."""
    logger.debug("Received request on /health")
    status_code = 200
    response = {
        'status': 'healthy',
        'checks': {
            'database': 'ok',
            'cloudflare_api': 'ok'
        }
    }

    # 1. check Database Connection
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        conn.close()
        logger.debug("Health check: Database connection successful.")
    except Exception as e:
        logger.error(f"Health check: Database connection failed: {e}")
        response['status'] = 'unhealthy'
        response['checks']['database'] = f"failed: {e}"
        status_code = 503 # service unavailable

    # 2. check Cloudflare API Connection
    api_token = os.getenv('CLOUDFLARE_API_TOKEN')
    if api_token: # only check if token is configured
        headers = {"Authorization": f"Bearer {api_token}"}
        # using very lightweight endpoint like listing zones with limit 1
        cf_endpoint = "https://api.cloudflare.com/client/v4/zones?per_page=1"
        try:
            cf_response = requests.get(cf_endpoint, headers=headers, timeout=5)
            if cf_response.status_code == 403: # specific check for bad token
                 logger.warning("Health check: Cloudflare API returned 403 Forbidden (check token).")
                 response['status'] = 'degraded' # service might work, but CF part has issues
                 response['checks']['cloudflare_api'] = 'forbidden (check token)'
                 if status_code == 200: status_code = 200
            elif not cf_response.ok: # catch other non-2xx errors
                 logger.warning(f"Health check: Cloudflare API check failed with status {cf_response.status_code}.")
                 response['status'] = 'degraded'
                 response['checks']['cloudflare_api'] = f"failed (status {cf_response.status_code})"
                 if status_code == 200: status_code = 200 # Or 503
            else:
                 logger.debug("Health check: Cloudflare API connection successful.")
                 # response['checks']['cloudflare_api'] remains 'ok'
        except requests.exceptions.Timeout:
            logger.warning("Health check: Cloudflare API check timed out.")
            response['status'] = 'degraded'
            response['checks']['cloudflare_api'] = 'timeout'
            if status_code == 200: status_code = 200 # Or 503
        except requests.exceptions.RequestException as e:
            logger.warning(f"Health check: Cloudflare API connection error: {e}")
            response['status'] = 'degraded'
            response['checks']['cloudflare_api'] = f"connection error: {e}"
            if status_code == 200: status_code = 200 # Or 503
    else:
        logger.warning("Health check: Skipping Cloudflare API check (no token found).")
        response['checks']['cloudflare_api'] = 'skipped (no token)'
        # don't change overall status just because token is missing

    return jsonify(response), status_code


# --- Initialize DB (Scheduler disabled for free hosting compatibility) ---
try:
    init_db()
    logger.info("Database initialized successfully.")
    logger.warning("Background scheduler disabled (not supported on free hosting). Use /cleanup endpoint for manual cleanup if needed.")
except Exception as e:
    logger.exception("CRITICAL: Error during database setup.")
    import sys
    sys.exit(1)

# Manual cleanup endpoint (call this with cron or manually)
@app.route('/cleanup', methods=['POST'])
@limiter.limit("5 per hour")
@require_api_password
def manual_cleanup():
    """Manual cleanup of expired emails - requires API password"""
    try:
        cleanup_expired_emails()
        return jsonify({'message': 'Cleanup completed successfully'}), 200
    except Exception as e:
        logger.exception("Error during manual cleanup")
        return jsonify({'error': str(e)}), 500


# --- Main Execution ---
if __name__ == '__main__':
    logger.info("Running Flask development server...")
    port = int(os.getenv('PORT', os.getenv('FLASK_RUN_PORT', 6020)))
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
