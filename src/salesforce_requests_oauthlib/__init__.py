'''
    Copyright (c) 2016, Salesforce.org
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Salesforce.org nor the names of
      its contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
'''

# TODO: saved refresh tokens may not play well with multiple clients running
#       at once
try:
    import BaseHTTPServer
except ImportError:
    import http.server as BaseHTTPServer
try:
    import thread
except ImportError:
    import _thread as thread
import os.path
import os
import time
import webbrowser
import pickle
import errno
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from oauthlib.oauth2.rfc6749.clients import LegacyApplicationClient
from oauthlib.oauth2.rfc6749.clients import ServiceApplicationClient
from abc import ABCMeta
from abc import abstractmethod
import six
import psycopg2
from psycopg2.extras import execute_values
from psycopg2.extensions import AsIs



default_token_path = \
    os.path.expanduser('~/.salesforce_requests_oauthlib')

default_refresh_token_filename = 'refresh_tokens.pickle'

base_url_template = \
    'https://{{0}}.salesforce.com/services/oauth2/{0}'

authorization_url_template = base_url_template.format(
    'authorize'
)

token_url_template = base_url_template.format(
    'token'
)


@six.add_metaclass(ABCMeta)
class TokenStorageMechanism:
    @abstractmethod
    def store(self, tokens):
        pass

    @abstractmethod
    def retrieve(self):
        pass


class HiddenLocalStorage(TokenStorageMechanism):
    def __init__(self, token_path=default_token_path):
        if not os.path.exists(token_path):
            try:
                os.makedirs(token_path)
            except OSError as e:  # Guard against race condition
                if e.errno != errno.EEXIST:
                    raise e

        self.full_token_path = os.path.join(
            token_path,
            default_refresh_token_filename
        )

    def store(self, tokens):
        # Yes, overwrite
        with open(self.full_token_path, 'wb') as fileh:
            pickle.dump(tokens, fileh)

    def retrieve(self):
        try:
            with open(self.full_token_path, 'rb') as fileh:
                return pickle.load(fileh)
        except IOError:
            return {}


class PostgresStorage(TokenStorageMechanism):
    def __init__(
        self,
        database_uri=None,
        schema_name='salesforce_requests_oauthlib'
    ):
        if database_uri is None:
            database_uri = os.environ['DATABASE_URL']

        self.table_name = 'refresh_tokens'
        self.schema_name = schema_name

        with psycopg2.connect(database_uri, sslmode='require') as pg_conn:
            pg_cursor = pg_conn.cursor()
            pg_cursor.execute(
                'SELECT COUNT(*) FROM information_schema.schemata '
                'WHERE schema_name = %s',
                (self.schema_name,)
            )
            schema_count = pg_cursor.fetchone()[0]

            if schema_count == 0:
                pg_cursor.execute('CREATE SCHEMA %s', (AsIs(self.schema_name),))
                pg_conn.commit()

            pg_cursor.execute('SET search_path TO %s', (AsIs(self.schema_name),))

            pg_cursor.execute(
                'SELECT COUNT(*) '
                'FROM information_schema.tables '
                'WHERE table_schema = %s '
                'AND table_name = %s '
                'AND table_type = %s',
                (self.schema_name, self.table_name, 'BASE TABLE')
            )
            table_count = pg_cursor.fetchone()[0]
            if table_count == 0:
                create_table_template = '''CREATE TABLE %s (
    username text primary key,
    refresh_token text
)'''
                pg_cursor.execute(
                    create_table_template,
                    (AsIs(self.table_name),)
                )

        self.database_uri = database_uri

    def store(self, tokens):
        with psycopg2.connect(self.database_uri, sslmode='require') as pg_conn:
            pg_cursor = pg_conn.cursor()
            pg_cursor.execute('SET search_path TO %s', (AsIs(self.schema_name),))
            insert_stmt = '{0} %s ON CONFLICT (username) DO UPDATE SET refresh_token = EXCLUDED.refresh_token'.format(
                pg_cursor.mogrify(
                    'INSERT INTO %s (username, refresh_token) VALUES',
                    (AsIs(self.table_name),)
                ).decode()
            )
            execute_values(
                pg_cursor,
                insert_stmt,
                tokens.items()
            )

    def retrieve(self):
        to_return = {}

        # We'll reconnect every time, because it might be a long time between
        # DB access
        with psycopg2.connect(self.database_uri, sslmode='require') as pg_conn:
            pg_cursor = pg_conn.cursor()
            pg_cursor.execute('SET search_path TO %s', (AsIs(self.schema_name),))
            pg_cursor.execute(
                'SELECT username, refresh_token FROM %s',
                (AsIs(self.table_name),)
            )

            for result in pg_cursor.fetchall():
                to_return[result[0]] = result[1]

        return to_return


class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        if 'code=' in self.path:
            self.server.oauth2_full_path = 'https://{0}:{1}{2}'.format(
                self.server.server_name,
                str(self.server.server_port),
                self.path
            )
            self.send_response(200, 'OK')
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            def shutdown_server(server):
                server.shutdown()

            thread.start_new_thread(shutdown_server, (self.server,))


class SalesforceOAuth2Session(OAuth2Session):
    def __init__(self, client_id, client_secret, username,
                 sandbox=False,
                 local_server_settings=('localhost', 60443),
                 password=None,
                 ignore_cached_refresh_tokens=False,
                 version=None,
                 custom_domain=None,
                 oauth2client=None,
                 token_storage=None):

        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.local_server_settings = local_server_settings
        if custom_domain is not None:
            self.token_url = token_url_template.format(
                '{0}.my'.format(custom_domain)
            )
            self.authorization_url_location = authorization_url_template.format(
                '{0}.my'.format(custom_domain)
            )
        else:
            self.token_url = token_url_template.format(
                'test' if sandbox else 'login'
            )
            # Avoid name collision
            self.authorization_url_location = authorization_url_template.format(
                'test' if sandbox else 'login'
            )

        # NOTE: even though this says https://, if the Salesforce connected
        # app's Callback URL uses http://localhost, SF will redirect to
        # http://localhost, so the non-HTTPS HTTPServer() in
        # launch_webbrowser_flow() will still work
        self.callback_url = 'https://{0}:{1}'.format(
            self.local_server_settings[0],
            str(self.local_server_settings[1])
        )

        if oauth2client:
            client = oauth2client
        elif password is not None:
            client = LegacyApplicationClient(client_id=client_id)
        else:
            client = None

        # Side effect here is to set self.client_id
        super(SalesforceOAuth2Session, self).__init__(
            client_id=client_id,
            redirect_uri=self.callback_url,
            client=client
        )

        if isinstance(oauth2client, ServiceApplicationClient):
            # make JWT valid for only 3 minutes to prevent reuse later
            expires_at = time.time() + 180
            self.fetch_token(self.token_url, expires_at=expires_at)
        else:
            if token_storage is None:
                token_storage = HiddenLocalStorage

            if isinstance(token_storage, TokenStorageMechanism):
                self.token_storage = token_storage
            else:
                self.token_storage = token_storage()

            refresh_token = None

            if not ignore_cached_refresh_tokens:
                saved_refresh_tokens = self.token_storage.retrieve()
                if self.username in saved_refresh_tokens:
                    refresh_token = saved_refresh_tokens[self.username]

            if refresh_token is None:
                self.launch_flow()
            else:
                self.token = {
                    'token_type': 'Bearer',
                    'refresh_token': refresh_token,
                    'access_token': 'Would you eat them in a box?'
                }

                self.refresh_token()

        self.version = version
        if self.version is None:
            self.use_latest_version()

    def launch_flow(self):
        if self.password is None:
            self.launch_webbrowser_flow()
        else:
            self.launch_password_flow()

    def refresh_token(self):
        try:
            super(SalesforceOAuth2Session, self).refresh_token(
                self.token_url,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
        except InvalidGrantError:
            self.launch_flow()

    def use_latest_version(self):
        self.version = self.get('/services/data/').json()[-1]['version']

    def launch_webbrowser_flow(self):
        # Right now the webbrowser module doesn't properly open chrome when
        # it's the default browser on OS X.  As a workaround, force safari.
        import sys
        if sys.platform == 'darwin':
            browser = webbrowser.get('safari')
            browser.open(
                self.authorization_url(
                    self.authorization_url_location
                )[0],
                new=2,
                autoraise=True
            )
        else:
            webbrowser.open(
                self.authorization_url(
                    self.authorization_url_location
                )[0],
                new=2,
                autoraise=True
            )

        httpd = BaseHTTPServer.HTTPServer(
            self.local_server_settings,
            RequestHandler
        )

        httpd.timeout = 30

        httpd.serve_forever()
        httpd.server_close()

        self.fetch_token(
            token_url=self.token_url,
            authorization_response=httpd.oauth2_full_path,
            client_id=self.client_id,
            client_secret=self.client_secret
        )

        saved_refresh_tokens = self.token_storage.retrieve()

        saved_refresh_tokens[self.username] = self.token['refresh_token']

        self.token_storage.store(saved_refresh_tokens)

    def launch_password_flow(self):
        self.fetch_token(
            token_url=self.token_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
            username=self.username,
            password=self.password
        )

    def request(self, *args, **kwargs):
        version_substitution = True
        if 'version_substitution' in kwargs:
            version_substitution = kwargs['version_substitution']

        # Not checking the first two args for sanity - seems like overkill.
        url = args[1]

        if version_substitution:
            url = url.replace('vXX.X', 'v{0}'.format(
                str(self.version))
                    if hasattr(self, 'version') and self.version is not None
                    else ''
            )

        if 'instance_url' in self.token and url.startswith('/'):
            # Then it's relative
            # We append the instance_url for convenience
            url = '{0}{1}'.format(
                self.token['instance_url'],
                url
            )

        return super(SalesforceOAuth2Session, self).request(
            args[0],
            url,
            *args[2:],
            **kwargs
        )
