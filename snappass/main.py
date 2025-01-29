import os
import sys
import uuid
import logging
import redis # type: ignore
import random
import string
import smtplib
import sys
# import pam

from email.mime.text import MIMEText
from cryptography.fernet import Fernet
from flask import abort, Flask, render_template, request, jsonify, make_response # type: ignore
from redis.exceptions import ConnectionError # type: ignore
from urllib.parse import quote
from urllib.parse import unquote_plus
from urllib.parse import urljoin
from distutils.util import strtobool
# _ is required to get the Jinja templates translated
from flask_babel import Babel, _  # type: ignore # noqa: F401
# from flask_httpauth import HTTPBasicAuth


SMTP_SERVER = "your_smtp_here"
SMTP_FROM = "your_email_here"
SMTP_SUBJECT = "Snappass Password Notification"
NO_SSL = bool(strtobool(os.environ.get('NO_SSL', 'False')))
URL_PREFIX = os.environ.get('URL_PREFIX', None)
HOST_OVERRIDE = os.environ.get('HOST_OVERRIDE', None)
TOKEN_SEPARATOR = '~'

#Init PAM

# pam_auth = pam.pam()
# auth = HTTPBasicAuth()

# Initialize Flask Application
app = Flask(__name__)
if os.environ.get('DEBUG'):
    app.debug = True
app.secret_key = os.environ.get('SECRET_KEY', 'Secret Key')
app.config.update(
    dict(STATIC_URL=os.environ.get('STATIC_URL', 'static')))


# Get log level from the OS env, default to INFO only if not set in systemd
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()

# Validate log level
valid_log_levels = ["DEBUG", "INFO"]
if log_level not in valid_log_levels:
    log_level = "INFO"
    

def send_email(link, recipient_email):
    """
    Отправка email с ссылкой на пароль.
    """
    try:
        body = f"Password link: {link}"
        msg = MIMEText(body)
        msg["Subject"] = SMTP_SUBJECT
        msg["From"] = SMTP_FROM
        msg["To"] = recipient_email

        logging.info(f"Connecting to SMTP server: {SMTP_SERVER}")
        with smtplib.SMTP(SMTP_SERVER) as server:
            server.sendmail(SMTP_FROM, [recipient_email], msg.as_string())
        logging.info(f"Email sent successfully to {recipient_email}")
    except Exception as e:
        logging.error(f"Failed to send email to {recipient_email}: {str(e)}")
        sys.exit(1)
        

# Set up Babel
def get_locale():
    return request.accept_languages.best_match(['en', 'es', 'de', 'nl', 'fr'])


babel = Babel(app, locale_selector=get_locale)

# Initialize Redis
if os.environ.get('MOCK_REDIS'):
    from fakeredis import FakeStrictRedis # type: ignore

    redis_client = FakeStrictRedis()
elif os.environ.get('REDIS_URL'):
    redis_client = redis.StrictRedis.from_url(os.environ.get('REDIS_URL'))
else:
    redis_host = os.environ.get('REDIS_HOST', 'localhost')
    redis_port = os.environ.get('REDIS_PORT', 6379)
    redis_db = os.environ.get('SNAPPASS_REDIS_DB', 0)
    redis_client = redis.StrictRedis(
        host=redis_host, port=redis_port, db=redis_db)
REDIS_PREFIX = os.environ.get('REDIS_PREFIX', 'snappass')

TIME_CONVERSION = {'month': 2592000,'two weeks': 1209600, 'week': 604800, 'day': 86400,
                   'hour': 3600}
DEFAULT_API_TTL = 1209600
MAX_TTL = DEFAULT_API_TTL


def check_redis_alive(fn):
    def inner(*args, **kwargs):
        try:
            if fn.__name__ == 'main':
                redis_client.ping()
            return fn(*args, **kwargs)
        except ConnectionError as e:
            print('Failed to connect to redis! %s' % e.message)
            if fn.__name__ == 'main':
                sys.exit(0)
            else:
                return abort(500)

    return inner


def encrypt(password):
    """
    Take a password string, encrypt it with Fernet symmetric encryption,
    and return the result (bytes), with the decryption key (bytes)
    """
    encryption_key = Fernet.generate_key()
    fernet = Fernet(encryption_key)
    encrypted_password = fernet.encrypt(password.encode('utf-8'))
    return encrypted_password, encryption_key


def decrypt(password, decryption_key):
    """
    Decrypt a password (bytes) using the provided key (bytes),
    and return the plain-text password (bytes).
    """
    fernet = Fernet(decryption_key)
    return fernet.decrypt(password)


def parse_token(token):
    token_fragments = token.split(TOKEN_SEPARATOR, 1)  # Split once, not more.
    storage_key = token_fragments[0]

    try:
        decryption_key = token_fragments[1].encode('utf-8')
        decryption_key = decryption_key + b'=' * (-len(decryption_key) % 4)  # Restore '='
    except IndexError:
        decryption_key = None

    return storage_key, decryption_key


def as_validation_problem(request, problem_type, problem_title, invalid_params):
    base_url = set_base_url(request)

    problem = {
        "type": base_url + problem_type,
        "title": problem_title,
        "invalid-params": invalid_params
    }
    return as_problem_response(problem)


def as_not_found_problem(request, problem_type, problem_title, invalid_params):
    base_url = set_base_url(request)

    problem = {
        "type": base_url + problem_type,
        "title": problem_title,
        "invalid-params": invalid_params
    }
    return as_problem_response(problem, 404)


def as_problem_response(problem, status_code=None):
    if not isinstance(status_code, int) or not status_code:
        status_code = 400

    response = make_response(jsonify(problem), status_code)
    response.headers['Content-Type'] = 'application/problem+json'
    return response


@check_redis_alive
def set_password(password, ttl):
    """
    Encrypt and store the password for the specified lifetime.

    Returns a token comprised of the key where the encrypted password
    is stored, and the decryption key.
    """
    storage_key = REDIS_PREFIX + uuid.uuid4().hex
    encrypted_password, encryption_key = encrypt(password)
    redis_client.setex(storage_key, ttl, encrypted_password)
    encryption_key = encryption_key.decode('utf-8').rstrip('=')  # Remove '='
    token = TOKEN_SEPARATOR.join([storage_key, encryption_key])
    return token


@check_redis_alive
def get_password(token):
    """
    From a given token, return the decrypted password.

    If the token is invalid or decryption fails, the key is not deleted.
    """
    storage_key, decryption_key = parse_token(token)

    encrypted_password = redis_client.get(storage_key)

    if encrypted_password is None:
        logging.warning(f"Password for token {token} not found in Redis.")
        return None

    if decryption_key is not None:
        try:
            decrypted_password = decrypt(encrypted_password, decryption_key)
            redis_client.delete(storage_key)
            return decrypted_password.decode('utf-8')
        except Exception as e:
            logging.error(f"Decryption failed for token {token}: {str(e)}")
            return None

    redis_client.delete(storage_key) 
    return encrypted_password.decode('utf-8')


@check_redis_alive
def password_exists(token):
    storage_key, decryption_key = parse_token(token)
    return redis_client.exists(storage_key)


def empty(value):
    if not value:
        return True


def clean_input():
    """
    Make sure we're not getting bad data from the front end,
    format data to be machine readable
    """
    if empty(request.form.get('password', '')):
        abort(400)

    if empty(request.form.get('ttl', '')):
        abort(400)

    time_period = request.form['ttl'].lower()
    if time_period not in TIME_CONVERSION:
        abort(400)

    return TIME_CONVERSION[time_period], request.form['password']


def set_base_url(req):
    if NO_SSL:
        if HOST_OVERRIDE:
            base_url = f'http://{HOST_OVERRIDE}/'
        else:
            base_url = req.url_root
    else:
        if HOST_OVERRIDE:
            base_url = f'https://{HOST_OVERRIDE}/'
        else:
            base_url = req.url_root.replace("http://", "https://")
    if URL_PREFIX:
        base_url = base_url + URL_PREFIX.strip("/") + "/"
    return base_url

def gen_random_string(length=24):
    rnd = random.SystemRandom()
    pwd_chars = string.ascii_letters + string.digits + "!$%^&*_#@()=-+[]{}<>;:,.?"  
    return ''.join(rnd.choice(pwd_chars) for _ in range(length))



@app.before_request
def log_request_info():
    source_ip = request.headers.get('X-Real-IP', 'Not provided')
    logging.info(f"[{source_ip}] Processing request: {request.method} {request.url}")

    if log_level == "DEBUG":
        if request.is_json:
            logging.debug(f"Request JSON body: {request.json}")
        elif request.form:
            logging.debug(f"Request form data: {request.form}")
        else:
            logging.debug("Request does not contain JSON or form data.")


@app.after_request
def log_response_info(response):
    if log_level == "DEBUG":
        if response.content_type == "application/json":
            logging.debug(f"Response JSON body: {response.status_code} {response.get_json()}")
            logging.info(f"Response: {response.status_code} for {request.method} {request.url}")
        else:
            logging.debug(f"Response content type: {response.status_code} {response.content_type}, skipping detailed content.")
            logging.info(f"Response: {response.status_code} for {request.method}")

    if response.status_code == 200:
        content_type = response.content_type or "unknown"
        logging.info(f"Response content type: {response.status_code} {content_type}")
        
    return response


@app.route('/', methods=['GET'])
def index():
    random_password = gen_random_string()
    #return render_template('set_password.html')
    return render_template('set_password.html', random_password=random_password)


@app.route('/', methods=['POST'])
def handle_password():
    password = request.form.get('password')
    ttl = request.form.get('ttl')
    if clean_input():
        ttl = TIME_CONVERSION[ttl.lower()]
        token = set_password(password, ttl)
        base_url = set_base_url(request)
        link = base_url + quote(token, safe='~=')  # Prevent '=' from being encoded
        if request.accept_mimetypes.accept_json and not \
           request.accept_mimetypes.accept_html:
            return jsonify(link=link, ttl=ttl)
        else:
            return render_template('confirm.html', password_link=link)
    else:
        abort(500)


# @auth.verify_password
# def verify_password(username, password):
#     """
#     Check login and password through the PAM
#     """
#     return pam_auth.authenticate(username, password)


@app.route('/api/set_password/', methods=['POST'])
#@auth.login_required
def api_handle_password():
    """
    Basic AUTH required.
    """
    password = request.json.get('password')
    ttl = int(request.json.get('ttl', DEFAULT_API_TTL))
    if password and isinstance(ttl, int) and ttl <= MAX_TTL:
        token = set_password(password, ttl)
        base_url = set_base_url(request)
        link = base_url + quote(token, safe='~=')
        return jsonify(link=link, ttl=ttl)
    else:
        abort(500)



@app.route('/api/v2/passwords', methods=['POST'])
#@auth.login_required
def api_v2_set_password():
    """
    API для установки пароля. Требует Basic Auth.
    """
    password = request.json.get('password')
    ttl = int(request.json.get('ttl', DEFAULT_API_TTL))

    invalid_params = []

    if not password:
        invalid_params.append({
            "name": "password",
            "reason": "The password is required and should not be null or empty."
        })

    if not isinstance(ttl, int) or ttl > MAX_TTL:
        invalid_params.append({
            "name": "ttl",
            "reason": "The specified TTL is longer than the maximum supported."
        })

    if len(invalid_params) > 0:
        return as_validation_problem(
            request,
            "set-password-validation-error",
            "The password and/or the TTL are invalid.",
            invalid_params
        )

    token = set_password(password, ttl)
    url_token = quote(token, safe='~=')
    base_url = set_base_url(request)
    api_link = urljoin(base_url, request.path + "/" + url_token)
    web_link = urljoin(base_url, url_token)
    response_content = {
        "token": token,
        "links": [{
            "rel": "self",
            "href": api_link
        }, {
            "rel": "web-view",
            "href": web_link
        }],
        "ttl": ttl
    }
    return jsonify(response_content)


# Logger settings
logging.basicConfig(
    filename='/var/log/snappass.log',
    level=getattr(logging, log_level, logging.INFO),
    format='%(asctime)s [%(levelname)s] %(message)s'
)

pid = os.getpid()
logging.info(f"Log level dynamically set to: {log_level}")
logging.info(f"Starting Snappass using gunicorn with workers. Worker PID: {pid}")


@app.route('/api/v2/passwords/<token>', methods=['HEAD'])
def api_v2_check_password(token):
    token = unquote_plus(token)
    if not password_exists(token):
        # Return NotFound, to indicate that password does not exists (anymore or at all)
        return ('', 404)
    else:
        # Return OK, to indicate that password still exists
        return ('', 200)


@app.route('/api/v2/passwords/<token>', methods=['GET'])
def api_v2_retrieve_password(token):
    token = unquote_plus(token)
    password = get_password(token)
    if not password:
        # Return NotFound, to indicate that password does not exists (anymore or at all)
        return as_not_found_problem(
            request,
            "get-password-error",
            "The password doesn't exist.",
            [{"name": "token"}]
        )
    else:
        # Return OK and the password in JSON message
        return jsonify(password=password)


@app.route('/<password_key>', methods=['GET'])
def preview_password(password_key):
    password_key = unquote_plus(password_key)
    if not password_exists(password_key):
        return render_template('expired.html'), 404

    return render_template('preview.html')


@app.route('/<password_key>', methods=['POST'])
def show_password(password_key):
    password_key = unquote_plus(password_key)
    password = get_password(password_key)
    if not password:
        return render_template('expired.html'), 404

    return render_template('password.html', password=password)


@app.route('/_/_/health', methods=['GET'])
@check_redis_alive
def health_check():
    return {}


@app.route('/generate-password', methods=['POST'])
def generate_password():
    data = request.json
    length = int(data.get('length', 32))
    if length < 1 or length > 64:
        return jsonify({"error": "Invalid length."}), 400
    charset = string.ascii_letters + string.digits + "!$%^&*_#@()=-+[]{}<>;:,.?"
    password = ''.join(random.choices(charset, k=length))
    return jsonify({"password": password})


@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(
        f"Error occurred during request: {request.method} {request.url} - {str(e)}",
        exc_info=True
    )

    response = {
        "error": "Internal Server Error",
        "message": "An unexpected error occurred. Please contact support.",
        "details": str(e)
    }

    return jsonify(response), 500


@check_redis_alive
def main():
    app.run(host=os.environ.get('SNAPPASS_BIND_ADDRESS', '0.0.0.0'),
            port=os.environ.get('SNAPPASS_PORT', 5000))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        logging.error("Usage: send_email.py <password_link> <recipient_email>")
        sys.exit(1)

    password_link = sys.argv[1]
    recipient_email = sys.argv[2]

    logging.info(f"Processing email notification for link: {password_link}, recipient: {recipient_email}")
    send_email(password_link, recipient_email)