from ipaddress import ip_network as network
from wsa.route_processor import route_lookup, validate_route
from githubapi.utils import GithubAPI
from xml.etree import ElementTree as ET


def get_table():
    api = GithubAPI()
    route_content = api.get_file_content(file_path='wsa/wsa_routes.xml')

    routes = ET.fromstring(route_content)

    table = routes.find('routing_table/[routing_table_interface="Data"]/routes')

    return api, table, routes


def get_routes(dst: str=None):
    api, table, routes = get_table()

    if dst is not None:
        int_routes = table.findall('route/[gateway="internal_gateway"]/destination')
        ext_routes = table.findall('route/[gateway="external_gateway"]/destination')

        internal_routes = list(route.text for route in int_routes)
        external_routes = list(route.text for route in ext_routes)

        route = route_lookup(dst, internal_routes, external_routes)

        if route == network('0.0.0.0/0'):
            return 200, 'This destination follows the default route'
        else:
            route = table.find('route/[destination="{}"]'.format(route.with_prefixlen))

        return 200, '{:<6s} {:<20s} {:<15s}\n'.format(route[0].text, route[1].text, route[2].text)
    else:
        response = ''
        for route in table:
            response = response + '{:<6s} {:<20s} {:<15s}\n'.format(route[0].text, route[1].text, route[2].text)

        return 200, response


def add_route(prefix: str, gateway: str, requester: str):
    api, table, routes = get_table()

    try:
        prefix = network(prefix, strict=False)
    except ValueError as error:
        return 400, error

    if gateway.lower() not in ['internal', 'external']:
        return 400, 'Invalid gateway request'

    if gateway.lower() == 'internal':
        gateway = 'internal_gateway'
    else:
        gateway = 'external_gateway'

    int_routes = table.findall(f'route/[gateway="internal_gateway"]/destination')
    ext_routes = table.findall(f'route/[gateway="external_gateway"]/destination')

    int_routes = list(route.text for route in int_routes)
    ext_routes = list(route.text for route in ext_routes)

    # Validate that the requested route is needed
    if validate_route(prefix, gateway, int_routes, ext_routes) is False:
        return 400, f'Route Validation determined that {prefix.with_prefixlen} is not needed.  ' \
                    f'Reasons for failed route validation include:\n' \
                    f'\n\t• The route already exists or is handled by an aggregate route' \
                    f'\n\t• The route is either multicast or broadcast and is not supported' \
                    f'\n\t• The requested prefix is already handled as requested'

    route_name = str(max(list(int(e.text) for elem in list(table)
                              for e in list(elem)
                              if e.tag == 'route_name')) + 1)

    route = ET.fromstring(f"""
    <route>
    <route_name>{route_name}</route_name>
    <destination>{prefix}</destination>
    <gateway>{gateway}</gateway>
    </route>
    """)

    table.append(route)

    api.update_file(file_path='wsa/wsa_routes.xml', message=f'{route_name} - {prefix} via {gateway} by {requester}',
                    content=ET.tostring(routes))

    return 200, 'Route Added Successfully:\n\n{}'.format(ET.tostring(route, encoding='utf-8').decode('utf-8'))


def delete_route(prefix: str, gateway: str, requester: str):
    api, table, routes = get_table()

    try:
        prefix = network(prefix, strict=False)
    except ValueError as error:
        return 400, error

    route = table.find(f'route/[destination="{prefix}"]')

    if route is None:
        return 404, 'Route does not exist'

    table.remove(route)

    api.update_file(file_path='wsa/wsa_routes.xml', message=f'{prefix} via {gateway} removed from wsa_routes.xml',
                    content=ET.tostring(routes))

    return 200, 'Route Deleted Successfully by {}:\n\n{}'.format(requester,
                                                                 ET.tostring(route, encoding='utf-8').decode('utf-8'))
