import logging
from flask import Flask, request, Response
import os
import time
from hubmap_commons.hm_auth import AuthHelper
import requests
import json

logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)
LOG_FILE_NAME = "./log/assets-auth-" + time.strftime("%d-%m-%Y-%H-%M-%S") + ".log"

# Specify the absolute path of the instance folder and use the config file relative to the instance path
app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'),
            instance_relative_config=True)
app.config.from_pyfile('app.cfg')

GLOBUS_APP_CLIENT_ID = app.config['GLOBUS_APP_CLIENT_ID']
GLOBUS_APP_CLIENT_SECRET = app.config['GLOBUS_APP_CLIENT_SECRET']
ENTITY_API_URL = app.config['ENTITY_API_URL']

# Initialize AuthHelper class and ensure singleton
try:
    if not AuthHelper.isInitialized():
        auth_helper_instance = AuthHelper.create(GLOBUS_APP_CLIENT_ID, GLOBUS_APP_CLIENT_SECRET)

        print("Initialized AuthHelper class successfully :)")
    else:
        auth_helper_instance = AuthHelper.instance()
except Exception:
    msg = "Failed to initialize the AuthHelper class"
    # Log the full stack trace, prepend a line with our message
    print(msg)

is_local_logging = False


# Format the lambda event object for localhost logging
# Only called from the unit tests
def enable_local_logging():
    global is_local_logging
    is_local_logging = True


def log_message(event):
    if is_local_logging:
        print(json.dumps(event, indent=4))
    else:
        # This enables a multiline string in one row of the Cloudwatch logs
        # Otherwise each line of the JSON will be printed on a separate line in the logs
        # This is only needed when running on AWS
        print(json.dumps(event, indent=4).replace('\n', '\r'))


@app.before_first_request
def init():
    try:
        logger.setLevel(logging.INFO)
        logFH = logging.FileHandler(LOG_FILE_NAME)
        logger.addHandler(logFH)
        logger.info('APP STARTED')
    except Exception as e:
        print("Error opening log file during startup")
        print(str(e))


@app.route('/', methods=['GET'])
def home():
    return "This is SenNet file-assets-auth :)"


@app.route('/auth', methods=['GET'])
def auth():
    print('AUTH STARTING')
    print('HEADERS')
    print(request.headers)

    headers = request.headers
    x_original_uri_ = headers['X-Original-Uri']
    path = x_original_uri_.strip('/')
    ok_response = {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        }
    }
    unauthenticated_response = {
        "statusCode": 401,
        "headers": {
            "Content-Type": "application/json"
        }
    }
    unauthorized_response = {
        "statusCode": 403,
        "headers": {
            "Content-Type": "application/json"
        }
    }

    # Handle requests to /
    if len(path) == 0:
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            }
        }
    path_list = path.split('?')
    token = None

    # Check if the token query parameter was passed in the original uri
    # If the token is not present in the query string check for it in the authorization header
    if len(path_list) == 2:
        query = path_list[1].split('=')
        if query[0] == 'token':
            token = query[1]
            print('token from query string', token)
    elif 'Authorization' in headers:
        bearer_token = headers['Authorization']
        # Remove the `Bearer ` part of the token
        token = bearer_token[7:]
        print('token from auth header', token)
    else:
        pass

    dataset_id, file_name = path_list[0].split('/')
    print('Dataset ID: ' + dataset_id)
    print('File name: ' + file_name)

    print('ENTITY_API_PRIVATE_IP: ', ENTITY_API_URL)
    entity_response = make_api_request_get(ENTITY_API_URL + '/entities/' + dataset_id)
    print('ENTITY RESPONSE')
    log_message(entity_response.json())

    data_access_level = entity_response.json()['data_access_level']
    print(f'Data access level of dataset_id: {dataset_id} is {data_access_level}')

    if data_access_level == 'consortium':
        if token is None:
            print('Requested access to a consortium level dataset but no token was present')
            return unauthenticated_response
        print('HAS READ PRIVS RESPONSE')
        response = auth_helper_instance.has_read_privs(token)
        if isinstance(response, Response):
            print('Invalid token. It could be expired.')
            return unauthenticated_response
        if response:
            print('Token has read or write privs')
            return ok_response
        else:
            print('Token does not have read or write privs')
            return unauthorized_response
    elif data_access_level == 'protected':
        print('Files from protected datasets are not available')
        return unauthorized_response
    else:
        return ok_response
    # return 'auth'


def make_api_request_get(target_url):
    now = time.ctime(int(time.time()))

    print(f'Making an HTTP request to GET {target_url} at time {now}')

    # Use modified version of globus app secret from configuration as the internal token
    request_headers = create_request_headers_for_auth(auth_helper_instance.getProcessSecret())

    # Disable ssl certificate verification
    response = requests.get(url=target_url, headers=request_headers, verify=False)

    return response


# Create a dict with HTTP Authorization header with Bearer token
def create_request_headers_for_auth(token):
    auth_header_name = 'Authorization'
    auth_scheme = 'Bearer'

    headers_dict = {
        # Don't forget the space between scheme and the token value
        auth_header_name: auth_scheme + ' ' + token
    }

    return headers_dict
