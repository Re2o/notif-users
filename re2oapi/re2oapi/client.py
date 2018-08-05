import logging
import datetime
import iso8601
from pathlib import Path
import stat
import json
import requests
from requests.exceptions import HTTPError

from . import exceptions

# Number of seconds before expiration where renewing the token is done
TIME_FOR_RENEW = 60
# Default name of the file to store tokens
DEFAULT_TOKEN_FILENAME = '.re2o.token'


class Re2oAPIClient:
    """Wrapper to handle the requests to Re2o API in a seemless way.

    You must first initialize the client and then you can access
    the API with dedicated functions that handle the authentication
    process for you.
    """

    def __init__(self, hostname, username, password, token_file=None,
                 use_tls=True, log_level=logging.CRITICAL+10):
        """Creates an API client.

        Args:
            hostname: The hostname of the Re2o server to use.
            username: The username to use.
            password: The password to use.
            token_file: An optional path to the file where re2o tokens are
                stored. Used both for retrieving the token and saving it, so
                the file must be accessible for reading and writing. The
                default value is `None`, which indicated to use
                `$HOME/{DEFAULT_TOKEN_FILENAME}`.
            use_tls: A boolean to indicate whether the client should us TLS
                (recommended for production). The default is `True`.
            log_level: Control the logging level to use. The default is
                `logging.CRITICAL+10`. So nothing is logged.

        Raises:
            requests.exceptions.ConnectionError: Unable to resolve the
                provided hostname.
            requests.exceptions.HTTPError: The server used does not have a
                valid Re2o API.
            re2oapi.exceptions.InvalidCredentials: The credentials provided
                are not valid according to the Re2o server.
        """.format(DEFAULT_TOKEN_FILENAME=DEFAULT_TOKEN_FILENAME)

        # Enable logging
        self.log = logging.getLogger(__name__)
        if not self.log.hasHandlers():
            # Avoid multiplicating handlers
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s %(message)s"
            )
            handler.setFormatter(formatter)
            self.log.addHandler(handler)
        self.log.setLevel(log_level)

        self.log.info("Starting new Re2o API client.")
        self.log.debug("hostname = " + str(hostname))
        self.log.debug("username = " + str(username))
        self.log.debug("token_file = " + str(token_file))
        self.log.debug("use_tls = " + str(use_tls))

        self.use_tls = use_tls
        self.token_file = token_file or Path.home() / DEFAULT_TOKEN_FILENAME
        self.hostname = hostname
        self._username = username
        self._password = password
        # Try to fetch token from token file else get a new one from the
        # server
        try:
            self.token = self._get_token_from_file()
        except exceptions.APIClientGenericError:
            self._force_renew_token()

    @property
    def need_renew_token(self):
        """The token needs to be renewed.

        Returns:
            True is the token expiration time is within less than
                {TIME_FOR_RENEW} seconds.
        """.format(TIME_FOR_RENEW=TIME_FOR_RENEW)

        return self.token['expiration'] < \
                datetime.datetime.now(datetime.timezone.utc) + \
                datetime.timedelta(seconds=TIME_FOR_RENEW)

    def _get_token_from_file(self):
        self.log.debug("Retrieving token from token file '{}'."
                       .format(self.token_file))

        # Check the token file exists
        if not self.token_file.is_file():
            e = exceptions.TokenFileNotFound(self.token_file)
            self.log.error(e)
            raise e

        # Read the data in the file
        try:
            with self.token_file.open() as f:
                data = json.load(f)
        except Exception:
            e = exceptions.TokenFileNotReadable(self.token_file)
            self.log.error(e)
            raise e

        try:
            # Retrieve data for this hostname and this username in the file
            token_data = data[self.hostname][self._username]
            ret = {
                'token': token_data['token'],
                'expiration': iso8601.parse_date(token_data['expiration'])
            }
        except KeyError:
            e = exceptions.TokenNotInTokenFile(
                self._username,
                self.hostname,
                self.token_file
            )
            self.log.error(e)
            raise e
        else:
            self.log.debug("Token successfully retrieved from token "
                           "file '{}'.".format(self.token_file))
        return ret

    def _save_token_to_file(self):
        self.log.debug("Saving token to token file '{}'."
                       .format(self.token_file))

        try:
            # Read previous data to not erase other tokens
            with self.token_file.open() as f:
                data = json.load(f)
        except Exception:
            # Default value if file not readbale or data not valid JSON
            self.log.warning("Token file '{}' is not a valid JSON readable "
                             "file. Considered empty.".format(self.token_file))
            data = {}

        # Insert the new token in the data (replace old token if it exists)
        if self.hostname not in data.keys():
            data[self.hostname] = {}
        data[self.hostname][self._username] = {
            'token': self.token['token'],
            'expiration': self.token['expiration'].isoformat()
        }

        # Rewrite the token file and ensure only the user can read it
        # Fails silently if the file cannot be written.
        try:
            with self.token_file.open('w') as f:
                json.dump(data, f)
            self.token_file.chmod(stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            self.log.error("Token file '{}' could not be written. Passing."
                             .format(self.token_file))
        else:
            self.log.debug("Token sucessfully writen in token file '{}'."
                           .format(self.token_file))

    def _get_token_from_server(self):
        self.log.debug("Requesting a new token form server '{}' for user "
                       "'{}'.".format(self.hostname, self._username))

        # Perform the authentication request
        response = requests.post(
            self.get_url_for('token-auth'),
            data={'username': self._username, 'password': self._password}
        )
        self.log.debug("Response code: "+str(response.status_code))

        if response.status_code == requests.codes.bad_request:
            e = exceptions.InvalidCredentials(self._username, self.hostname)
            self.log.error(e)
            raise e
        response.raise_for_status()

        # Return the token and expiration time
        response = response.json()
        ret = {
            'token': response['token'],
            'expiration': iso8601.parse_date(response['expiration'])
        }
        self.log.debug("Token successfully retrieved from server '{}'."
                       .format(self.hostname))
        return ret

    def _force_renew_token(self):
        self.token = self._get_token_from_server()
        self._save_token_to_file()

    def get_token(self):
        """Retrieves the token to use for the current connection.

        Returns:
            The token to use in the request as an authentication. It is
            automatically renewed if needed.

        Raises:
            re2oapi.exceptions.InvalidCredentials: The token needs to be
                renewed but the given credentials are not valid.
        """
        if self.need_renew_token:
            # Renew the token only if needed
            self._force_renew_token()
        return self.token['token']

    def _request(self, method, url, headers={}, params={}, *args, **kwargs):
        self.log.info("Building the request {} {}.".format(method.upper(), url))

        # Update headers to force the 'Authorization' field with the right token
        self.log.debug("Forcing authentication token.")
        headers.update({
            'Authorization': 'Token {}'.format(self.get_token())
        })

        # Use a json format unless the user already specified something
        if not 'format' in params.keys():
            self.log.debug("Forcing JSON format response.")
            params.update({'format': 'json'})

        # Perform the request
        self.log.info("Performing request {} {}".format(method.upper(), url))
        response = getattr(requests, method)(
            url, headers=headers, params=params, *args, **kwargs
        )
        self.log.debug("Response code: "+str(response.status_code))

        if response.status_code == requests.codes.unauthorized:
            # Force re-login to the server (case of a wrong token but valid
            # credentials) and then retry the request without catching errors.
            self.log.warning("Token refused. Trying to refresh the token.")
            self._force_renew_token()

            headers.update({
                'Authorization': 'Token {}'.format(self.get_token())
            })
            self.log.info("Re-performing the request {} {}"
                           .format(method.upper(), url))
            response = getattr(requests, method)(
                url, headers=headers, params=params, *args, **kwargs
            )
            self.log.debug("Response code: "+str(response.status_code))

        if response.status_code == requests.codes.forbidden:
            e = exceptions.PermissionDenied(method, url, self._username)
            self.log.debug(e)
            raise e
        response.raise_for_status()

        ret = response.json()
        self.log.debug("Request {} {} successful.".format(method, url))
        return ret

    def delete(self, *args, **kwargs):
        """Performs a DELETE request.

        DELETE request on a given URL that acts like `requests.delete` except
        that authentication to the API is automatically done and JSON response
        is decoded.

        Args:
            url: The URL of the requests.
            *args: See `requests.delete` parameters.
            **kwargs: See `requests.delete` parameters.

        Returns:
            The JSON-decoded result of the request.

        Raises:
            requests.exceptions.RequestException: An error occured while
                performing the request.
            exceptions.PermissionDenied: The user does not have the right
                to perform this request.
        """
        return self._request('delete', *args, **kwargs)

    def get(self, *args, **kwargs):
        """Performs a GET request.

        GET request on a given URL that acts like `requests.get` except that
        authentication to the API is automatically done and JSON response is
        decoded.

        Args:
            url: The URL of the requests.
            *args: See `requests.get` parameters.
            **kwargs: See `requests.get` parameters.

        Returns:
            The JSON-decoded result of the request.

        Raises:
            requests.exceptions.RequestException: An error occured while
                performing the request.
            exceptions.PermissionDenied: The user does not have the right
                to perform this request.
        """
        return self._request('get', *args, **kwargs)

    def head(self, *args, **kwargs):
        """Performs a HEAD request.

        HEAD request on a given URL that acts like `requests.head` except that
        authentication to the API is automatically done and JSON response is
        decoded.

        Args:
            url: The URL of the requests.
            *args: See `requests.head` parameters.
            **kwargs: See `requests.head` parameters.

        Returns:
            The JSON-decoded result of the request.

        Raises:
            requests.exceptions.RequestException: An error occured while
                performing the request.
            exceptions.PermissionDenied: The user does not have the right
                to perform this request.
        """
        return self._request('get', *args, **kwargs)

    def option(self, *args, **kwargs):
        """Performs a OPTION request.

        OPTION request on a given URL that acts like `requests.option` except
        that authentication to the API is automatically done and JSON response
        is decoded.

        Args:
            url: The URL of the requests.
            *args: See `requests.option` parameters.
            **kwargs: See `requests.option` parameters.

        Returns:
            The JSON-decoded result of the request.

        Raises:
            requests.exceptions.RequestException: An error occured while
                performing the request.
            exceptions.PermissionDenied: The user does not have the right
                to perform this request.
        """
        return self._request('get', *args, **kwargs)

    def patch(self, *args, **kwargs):
        """Performs a PATCH request.

        PATCH request on a given URL that acts like `requests.patch` except
        that authentication to the API is automatically done and JSON response
        is decoded.

        Args:
            url: The URL of the requests.
            *args: See `requests.patch` parameters.
            **kwargs: See `requests.patch` parameters.

        Returns:
            The JSON-decoded result of the request.

        Raises:
            requests.exceptions.RequestException: An error occured while
                performing the request.
            exceptions.PermissionDenied: The user does not have the right
                to perform this request.
        """
        return self._request('patch', *args, **kwargs)

    def post(self, *args, **kwargs):
        """Performs a POST request.

        POST request on a given URL that acts like `requests.post` except that
        authentication to the API is automatically done and JSON response is
        decoded.

        Args:
            url: The URL of the requests.
            *args: See `requests.post` parameters.
            **kwargs: See `requests.post` parameters.

        Returns:
            The JSON-decoded result of the request.

        Raises:
            requests.exceptions.RequestException: An error occured while
                performing the request.
            exceptions.PermissionDenied: The user does not have the right
                to perform this request.
        """
        return self._request('post', *args, **kwargs)

    def put(self, *args, **kwargs):
        """Performs a PUT request.

        PUT request on a given URL that acts like `requests.put` except that
        authentication to the API is automatically done and JSON response is
        decoded.

        Args:
            url: The URL of the requests.
            *args: See `requests.put` parameters.
            **kwargs: See `requests.put` parameters.

        Returns:
            The JSON-decoded result of the request.

        Raises:
            requests.exceptions.RequestException: An error occured while
                performing the request.
            exceptions.PermissionDenied: The user does not have the right
                to perform this request.
        """
        return self._request('put', *args, **kwargs)

    def get_url_for(self, endpoint):
        """Retrieve the complete URL to use for a given endpoint's name.

        Args:
            endpoint: The path of the endpoint.
            **kwargs: A dictionnary with the parameter to use to build the
                URL (using .format() syntax)

        Returns:
            The full URL to use.

        Raises:
            re2oapi.exception.NameNotExists: The provided name does not
                correspond to any endpoint.
        """
        return '{proto}://{host}/{namespace}/{endpoint}'.format(
            proto=('https' if self.use_tls else 'http'),
            host=self.hostname,
            namespace='api',
            endpoint=endpoint
        )

    def list(self, endpoint, max_results=None, params={}):
        """List all objects on the server that corresponds to the given
        endpoint. The endpoint must be valid for listing objects.

        Args:
            endpoint: The path of the endpoint.
            max_results: A limit on the number of result to return
            params: See `requests.get` params.

        Returns:
            The list of all the objects serialized as returned by the API.

        Raises:
            requests.exceptions.RequestException: An error occured while
                performing the request.
            exceptions.PermissionDenied: The user does not have the right
                to perform this request.
        """
        self.log.info("Starting listing objects under '{}'"
                      .format(endpoint))
        self.log.debug("max_results = "+str(max_results))

        # For optimization, list all results in one page unless the user
        # is forcing the use of a different `page_size`.
        if not 'page_size' in params.keys():
            self.log.debug("Forcing 'page_size' parameter to 'all'.")
            params['page_size'] = max_results or 'all'

        # Performs the request for the first page
        response = self.get(
            self.get_url_for(endpoint),
            params=params
        )
        results = response['results']

        # Get all next pages and append the results
        while response['next'] is not None and \
                (max_results is None or len(results) < max_results):
            response = self.get(response['next'])
            results += response['results']

        # Returns the exact number of results if applicable
        ret = results[:max_results] if max_results else results
        self.log.debug("Listing objects under '{}' successful"
                       .format(endpoint))
        return ret

    def count(self, endpoint, params={}):
        """Count all objects on the server that corresponds to the given
        endpoint. The endpoint must be valid for listing objects.

        Args:
            endpoint: The path of the endpoint.
            params: See `requests.get` params.

        Returns:
            The number of objects on the server as returned by the API.

        Raises:
            requests.exceptions.RequestException: An error occured while
                performing the request.
            exceptions.PermissionDenied: The user does not have the right
                to perform this request.
        """
        self.log.info("Starting counting objects under '{}'"
                      .format(endpoint))

        # For optimization, ask for only 1 result (so the server will take
        # less time to process the request) unless the user is forcing the
        # use of a different `page_size`.
        if not 'page_size' in params.keys():
            self.log.debug("Forcing 'page_size' parameter to '1'.")
            params['page_size'] = 1

        # Performs the request and return the `count` value in the response.
        ret = self.get(
            self.get_url_for(endpoint),
            params=params
        )['count']

        self.log.debug("Counting objects under '{}' successful"
                       .format(endpoint))
        return ret

    def view(self, endpoint, params={}):
        """Retrieved the details of an object from the server that corresponds
        to the given endpoint.

        Args:
            endpoint: The path of the endpoint.
            params: See `requests.get` params.

        Returns:
            The serialized data of the queried object as returned by the API.

        Raises:
            requests.exceptions.RequestException: An error occured while
                performing the request.
            exceptions.PermissionDenied: The user does not have the right
                to perform this request.
        """
        self.log.info("Starting viewing an object under '{}'"
                      .format(endpoint))
        ret = self.get(
            self.get_url_for(endpoint),
            params=params
        )

        self.log.debug("Viewing object under '{}' successful"
                       .format(endpoint))
        return ret
