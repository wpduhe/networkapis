import asyncio
import json
import os
import time
import re
import requests
import sys
import urllib3
import logging
from aiohttp import ClientSession, FormData, CookieJar
from types import SimpleNamespace


formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03dZ - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%Y-%m-%dT%H:%M:%S')

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

logging.basicConfig(level=logging.DEBUG, handlers=[handler])
logger = logging.getLogger(__name__)

logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.WARNING)

urllib3.disable_warnings()


def generate_files():
    logger.debug('Generating files')
    resp = requests.get('https://pyapis.ocp.app.medcity.net/apis/wsa/routes', verify=False)

    generic_route_data = resp.text.strip().split('\n')

    for dc in data:
        for environment in data[dc]['environments']:
            with open(f'{dc}_{environment}.dat', 'w') as file:
                for name, entry in enumerate(generic_route_data, start=101):
                    entry = re.findall(r'\S+', entry)
                    file.write(f'{name} {entry[1]} {data[dc]["environments"][environment][entry[2]]}\n')


def remove_files():
    logger.debug('Removing files')
    for dc in data:
        for environment in data[dc]['environments']:
            os.remove(f'{dc}_{environment}.dat')


async def main(loop: asyncio.AbstractEventLoop):
    tasks = []
    for environment in data[site]['environments']:
        for wsa in data[site]['environments'][environment]['wsaList']:
            use_file = f'{site}_{environment}.dat'
            tasks.append(loop.create_task(deploy(use_file, wsa)))

    for task in tasks:
        _ = await task

    return None


async def deploy(file: str, wsa: dict):
    wsa = SimpleNamespace(**wsa)
    async with (ClientSession(cookie_jar=CookieJar(unsafe=True)) as session):
        session_data = SimpleNamespace(session=session, csrf_key=None, base_url=f'https://{wsa.mgmtIP[:-3]}:8443',
                                       use_file=file, cookie='')
        # logger.debug(f'base_url={session_data.base_url}, csrf_key={str(session_data.csrf_key)}, '
        #              f'data_file={session_data.use_file}')

        # Navigate to login page
        # Here we retrieve hidden input values for the form: referrer, screen, CSRFKey
        # We also acquire the session cookie named "sid"
        user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

        login_page_resp = await session_data.session.get(session_data.base_url + '/login', headers=user_agent,
                                                         ssl=False)
        session_cookie = re.search('sid=\w+', login_page_resp.headers.get('set-cookie')).group()

        # logger.debug(f'{wsa.hostname} session cookie: {session_cookie}')

        # Update headers with session cookie
        session_data.session.headers.update(Cookie=session_cookie, Origin=session_data.base_url,
                                            Host=f'{wsa.mgmtIP[:-3]}:8443')
        session_data.session.headers.update({'Upgrade-Insecure-Requests': '1'})

        login_page_resp = await session_data.session.get(session_data.base_url + '/login?redirects=1', headers=user_agent,
                                                         ssl=False)
        login_page_text = await login_page_resp.text()

        session_data.session.headers.update({'Origin': session_data.base_url})

        # logger.debug(f'{wsa.hostname} current headers: {session_data.session.headers}')

        # Retrieve CSRF Key for completing forms
        session_data.csrf_key = re.search(r'CSRFKey=([a-z0-9-]+)', login_page_text).group(1)
        # logger.debug(f'{wsa.hostname} CSRF Key set: {session_data.csrf_key}')

        # Generate login form data
        login_data = FormData()
        login_data.add_field(name='action', value='Login')
        login_data.add_field(name='username', value=os.getenv('netmgmtuser'))
        login_data.add_field(name='password', value=os.getenv('netmgmtpass'))
        login_data.add_field(name='referrer', value='')
        login_data.add_field(name='screen', value='login')
        login_data.add_field(name='CSRFKey', value=session_data.csrf_key)

        # Login to the WSA
        login_resp =  await session_data.session.post(f'{session_data.base_url}/login', headers=user_agent,
                                                      data=login_data, ssl=False)

        # logger.debug(f'{wsa.hostname} Login POST Response: {login_resp.status}')

        # Navigate to routes page, we will check the success of the login process here
        route_page = await session_data.session.get(f'{session_data.base_url}/network/routes', headers=user_agent,
                                                    ssl=False)
        route_page_text = await route_page.text()
        # logger.debug(f'{wsa.hostname} Route page status: {route_page.status}')
        # logger.debug(f'{wsa.hostname} Route page reason: {route_page.reason}')
        logger.debug(f'{wsa.hostname} Successfully logged in: {"logged in as:" in route_page_text.lower()}')

        # Newer AsyncOS versions seem to change the CSRF Key from one page to the next. Getting new key
        session_data.csrf_key = re.search(r'CSRFKey=([a-z0-9-]+)', route_page_text).group(1)
        # logger.debug(f'{wsa.hostname} updated CSRF Key to: {session_data.csrf_key}')

        # Upload routes to the WSAs
        file_data = FormData()
        file_data.add_field(name='action', value='Import')
        file_data.add_field(name='interface_type', value='Data')
        file_data.add_field(name='screen', value='network.routes')
        file_data.add_field(name='file', filename=session_data.use_file,
                            value=open(session_data.use_file, 'r').read())
        file_data.add_field(name='CSRFKey', value=session_data.csrf_key)

        # logger.debug(f'{session_data.session.headers}')

        route_upload_resp = await session_data.session.post(f'{session_data.base_url}/network/routes',
                                                            headers=user_agent, data=file_data, ssl=False)
        route_upload_success = "Routes were successfully loaded" in await route_upload_resp.text()
        # logger.debug(f'{wsa.hostname} Route upload page: {await route_upload_resp.text()}')
        # Log whether the routes were successfully uploaded
        logger.debug(f'{wsa.hostname} Route upload successful: {route_upload_success}')


        # Commit the changes if the upload was successful
        if route_upload_success:
            commit_data = FormData()
            commit_data.add_field(name='action', value='Commit')
            commit_data.add_field(name='screen', value='commit')
            commit_data.add_field(name='logout', value='')
            commit_data.add_field(name='comment', value='')
            commit_data.add_field(name='CSRFKey', value=session_data.csrf_key)

            logger.debug(f'{wsa.hostname} changes being committed')
            commit_resp =  await session_data.session.post(f'{session_data.base_url}/commit', data=commit_data,
                                                           ssl=False)
            logger.debug(f'{wsa.hostname} changes successfully committed: {commit_resp.status == 200}')

        # Logout of the WSA
        logout_resp = await session_data.session.get(session_data.base_url + '/login?action=Logout', ssl=False)
        logger.debug(f'{wsa.hostname} Logout: {logout_resp.status}')


if __name__ == '__main__':
    start_time = time.perf_counter()
    site = sys.argv[1].upper()

    data = json.load(open('data/wsa.json'))

    generate_files()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    loop.run_until_complete(main(loop))

    remove_files()
    logger.debug(f'Completed route deployment to {site} in {round(time.perf_counter() - start_time, 3)} seconds')


if __name__ == 'deploy_routes_handler':
    # TODO: Maybe figure this out....?
    start_time = time.perf_counter()
    data = json.load(open('data/wsa.json'))

    generate_files()

    for site in data:
        logger.debug(f'Processing {site}')
        # loop = asyncio.new_event_loop()
        # asyncio.set_event_loop(loop)
        #
        # loop.run_until_complete(main(loop))

    remove_files()
    logger.debug(f'Completed route deployment for all sites in {round(time.perf_counter() - start_time, 3)} seconds')
