import asyncio, json, os, time, re
from aiohttp import ClientSession, FormData, CookieJar
from xml.etree import ElementTree as ET
from bs4 import BeautifulSoup
from githubapi.utils import GithubAPI


def deploy_wsa_routes(loop: asyncio.AbstractEventLoop, site=''):
    start_time = time.perf_counter()

    def main():
        loop.run_until_complete(setup(loop))

        # Clean up routes
        for key in data:
            for environment in data[key]['environments']:
                os.remove(f'{key}_{environment}.dat')

    def generate_tables():
        for key in data:
            for environment in data[key]['environments']:
                site_table = ET.fromstring(ET.tostring(table, encoding='utf-8').decode('utf-8'))
                external = site_table.findall('route/[gateway="external_gateway"]/gateway')
                internal = site_table.findall('route/[gateway="internal_gateway"]/gateway')

                for elem in external:
                    elem.text = data[key]['environments'][environment]['external_gateway']

                for elem in internal:
                    elem.text = data[key]['environments'][environment]['internal_gateway']

                with open(f'{key}_{environment}.dat', 'w') as f:
                    for route in site_table:
                        f.write(f'{route[0].text} {route[1].text} {route[2].text}\n')

    async def setup(s_loop):
        # print('Generating Tables...')
        generate_tables()
        # print('Tables Generated')

        tasks = []
        if site == '':
            for key in data:
                for environment in data[key]['environments']:
                    for wsa in data[key]['environments'][environment]['wsaList']:
                        use_file = f'{key}_{environment}'
                        tasks.append(s_loop.create_task(deploy(use_file, wsa)))
        else:
            for environment in data[site]['environments']:
                for wsa in data[site]['environments'][environment]['wsaList']:
                    use_file = f'{site}_{environment}'
                    tasks.append(s_loop.create_task(deploy(use_file, wsa)))

        for task in tasks:
            _ = await task

    def login_data(soup):
        form = soup.form
        form = ET.fromstring(str(form))

        referrer = form.find('input/[@name="referrer"]')
        screen = form.find('input/[@name="screen"]')
        csrf_key = form.find('input/[@name="CSRFKey"]')

        d = {
            'action': 'Login',
            'username': os.getenv('netmgmtuser'),
            'password': os.getenv('netmgmtpass'),
            'action_type': 'ajax_validation',
            'referrer': referrer.attrib['value'],
            'screen': screen.attrib['value'],
            'CSRFKey': csrf_key.attrib['value']
        }
        return d

    def session_handler(resp_headers, session):
        # return print('Disabled Session Handler')
        session.headers = dict(resp_headers)
        try:
            session.headers['Cookie'] = session.headers.pop('Set-Cookie')
            session.headers['Cookie'] = session.headers['Cookie'][:session.headers['Cookie'].index(';')]
        except KeyError:
            pass

    async def deploy(env, wsa):
        async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as session:
            session.env = env
            session.headers = {}
            session.url = 'https://{}:8443'.format(wsa['mgmtIP'].split('/')[0])
            try:
                session.csrfKey = await login(session)
                # print(f'{session.url} CSRF Key Set to {session.csrfKey}')
            except AttributeError:
                session.results = {
                    'Failure': 'Login Process Failed'
                }
                resps.append({wsa['hostname']: session.results})
            try:
                session.results = {
                    'route_load_response': await upload_routes(session),
                    'commit_response': await commit(session)
                }
                _ = await logout(session)
                resps.append({wsa['hostname']: session.results})
            except:
                session.results = {
                    'Results': 'Failed'
                }
                resps.append({wsa['hostname']: session.results})

    async def login(session):
        # print(f'Logging into {session.url}')
        async with await session.get(session.url, ssl=False) as r:
            # print(f'{session.url} Initial GET Request Made')
            assert r.status == 200
            # print(await r.read())
            # print(f'{session.url} Headers found for Session\n', r.headers)
            # print(f'{session.url} Cookies found for Session\n', r.cookies)

            session_handler(r.headers, session)

            soup = BeautifulSoup(await r.text())
            # print('Parsing GET request for key')
            d = login_data(soup)
            # print('Key Found and added to Login Data')
            _ = await r.release()

        session.headers['X-Requested-With'] = 'XMLHttpRequest'
        session.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        # print(f'{session.url} About to send first login POST: ')
        async with await session.post(f'{session.url}/login', data=d, headers=session.headers, ssl=False) as r:
            assert r.status == 200
            # print(f'{session.url} first login POST sent: ', r.status, '\n', r.headers, '\n', await r.text())
            s = await r.release()

        print(f'{session.url} About to send second login POST: ', session.headers)
        del d['action_type']
        session.headers['X-Requested-With'] = 'XMLHttpRequest'
        session.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        async with await session.post(f'{session.url}/login', data=d, headers=session.headers, ssl=False) as r:
            assert r.status == 200
            # print(f'{session.url} second login POST: ', r.status, '\n', await r.text())
            s = await r.release()

        # Obtain Session CSRFKey for filling out forms
        del session.headers['Content-Type']
        # print(f'{session.url} Navigate to configuration page')
        async with await session.get(f'{session.url}/system_administration/configuration/configuration_file',
                                     headers=session.headers, ssl=False) as r:
            assert r.status == 200
            csrfkey = re.search('CSRFKey=[a-z0-9-]+', await r.text()).group()[8:]
            # print(f'{session.url} CSRFKey {csrfkey}')
            # print(f'{session.url} csrfKey retrieved: About to return')
            # print(f'{session.url} Configuration Page: ', r.status, '\n', await r.text())
            s = await r.release()

        return csrfkey

    async def upload_routes(session):
        file_data = FormData()
        file_data.add_field(name='action', value='Import')
        file_data.add_field(name='interface_type', value='Data')
        file_data.add_field(name='screen', value='network.routes')
        file_data.add_field(name='file', filename=f'{session.env}.dat',
                            value=open(f'{session.env}.dat', 'r').read())
        try:
            file_data.add_field(name='CSRFKey', value=session.csrfKey)
        except:
            print('Failed at CSRFKey')

        # print(f'{session.url} Form Data created')

        # print(f'{session.url} About to upload routes')
        # async with await session.get(f'{session.url}/network/routes', ssl=False) as r:
        #     assert r.status == 200
        #     s = await r.release()
        try:
            async with await session.post(f'{session.url}/network/routes', data=file_data, headers=session.headers,
                                          ssl=False) as r:
                assert r.status == 200
                # print(f'{session.url} Would be uploading routes here...')
                # loadResp = {
                #     'resp_status': r.status
                # }
                # print(f'{session.url} Routes Uploaded', r.status, '\n', await r.text())

            return {'resp_status': r.status}
        except AssertionError:
            return {'resp_status': f'Failure: {r.status}'}

    async def commit(session):
        commit_data = FormData()
        commit_data.add_field(name='action', value='Commit')
        commit_data.add_field(name='screen', value='commit')
        commit_data.add_field(name='logout', value='')
        commit_data.add_field(name='comment', value='')
        commit_data.add_field(name='CSRFKey', value=session.csrfKey)

        # print(f'{session.url} About to Commit Changes')
        try:
            async with await session.post(f'{session.url}/commit', data=commit_data,
                                          headers=session.headers, ssl=False) as r:
                assert r.status == 200
                # commitResp = {
                #     'resp_status': r.status
                # }
                # print(f'{session.url} Committed Changes:', r.status, '\n', await r.text())

            return {'resp_status': r.status}
        except AssertionError:
            return {'resp_status': f'Failure: {r.status}'}

    async def logout(session):
        # print(f'{session.url} About to Log Out')
        try:
            async with await session.get(f'{session.url}/login?action=Logout', headers=session.headers, ssl=False) as r:
                assert r.status == 200
                # print(f'{session.url} Logged out:', r.status, '\n', await r.text())
        except AssertionError:
            pass

    # Get WSA JSON data
    data = json.load(open('data/wsa.json', 'r'))

    # Check to see if requested site is in the environment list
    if site != '' and site not in data.keys():
        return 'Invalid Site Provided', 'Deploy did not run'

    api = GithubAPI()
    routes_content = api.get_file_content('wsa/wsa_routes.xml')

    routes = ET.fromstring(routes_content)

    table = routes.find('routing_table/[routing_table_interface="Data"]/routes')

    resps = []

    main()
    elapsed = round(time.perf_counter() - start_time)

    # print(f'Process completed in {elapsed} seconds')

    return f'Completed in {elapsed} seconds', resps
