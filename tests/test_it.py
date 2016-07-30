from pytest import fixture
from getpass import getpass
from salesforce_requests_oauthlib import SalesforceOAuth2Session

test_settings_path = 'test_settings'


@fixture(scope='module')
def get_oauth_info():
    # Yes, it's annoying that you can't see the three of these that are not
    # secret echoed.  But getpass() is smart about where it opens the input
    # stream, so I'm using it for now.
    return (
        getpass('Enter oauth2 client identifier: '),
        getpass('Enter oauth2 client secret: '),
        getpass('Enter username: '),
        getpass('Enter yes if sandbox: ') == 'yes'
    )


@fixture(scope='module')
def setup_local_webserver_key(tmpdir_factory, request):
    settings_dir = tmpdir_factory.mktemp(test_settings_path)
    SalesforceOAuth2Session.generate_local_webserver_key(
        settings_path=str(settings_dir)
    )

    def fin():
        settings_dir.remove()
    request.addfinalizer(fin)

    return str(settings_dir)


def test_password_flow(get_oauth_info, setup_local_webserver_key):
    session = SalesforceOAuth2Session(
        get_oauth_info[0],
        get_oauth_info[1],
        get_oauth_info[2],
        sandbox=get_oauth_info[3],
        password=getpass('Enter password for {0}: '.format(
            get_oauth_info[2]
        )),
        ignore_cached_refresh_tokens=True
    )
    newest_version = session.get('/services/data/').json()[-1]
    response = session.get('/services/data/v{0}/sobjects/Contact'.format(
        newest_version['version']
    )).json()
    print response
    assert u'objectDescribe' in response


def test_webbrowser_flow(get_oauth_info, setup_local_webserver_key):
    session = SalesforceOAuth2Session(
        get_oauth_info[0],
        get_oauth_info[1],
        get_oauth_info[2],
        setup_local_webserver_key,
        get_oauth_info[3],
        ignore_cached_refresh_tokens=True
    )
    newest_version = session.get('/services/data/').json()[-1]
    response = session.get('/services/data/v{0}/sobjects/Contact'.format(
        newest_version['version']
    )).json()
    assert u'objectDescribe' in response

    # Test that refresh token recovery works
    session = SalesforceOAuth2Session(
        get_oauth_info[0],
        get_oauth_info[1],
        get_oauth_info[2],
        setup_local_webserver_key,
        get_oauth_info[3]
    )
    response = session.get('/services/data/v{0}/sobjects/Contact'.format(
        newest_version['version']
    )).json()
    assert u'objectDescribe' in response
