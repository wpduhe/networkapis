from ipaddress import ip_network as network
from xml.etree import ElementTree
from githubapi.utils import GithubAPI


def route_lookup(prefix, int_routes, ext_routes):
    prefix = network(prefix, strict=False)

    matches = []

    for route in int_routes:
        route = network(route, strict=False)

        if route.overlaps(prefix):
            matches.append(route)

    ext_routes.append('0.0.0.0/0')
    for route in ext_routes:
        route = network(route, strict=False)

        if route.overlaps(prefix):
            matches.append(route)

    match = network('0.0.0.0/0')

    for route in matches:
        if route.prefixlen > match.prefixlen:
            match = route
        else:
            continue

    return match


def validate_route(prefix, gateway, int_routes, ext_routes):
    int_routes = list(set(int_routes))
    ext_routes = list(set(ext_routes))

    int_routes.sort()
    ext_routes.sort()

    prefix = network(prefix, strict=False)

    if prefix == network('0.0.0.0/0') or prefix == network('255.255.255.255') or \
            prefix.overlaps(network('224.0.0.0/3')):
        return False

    def iroute_compare(ext_overlap=None):
        override = False

        for iroute in int_routes:
            # Check for internal aggregate routes that may already cover the requested route
            iroute = network(iroute, strict=False)

            if ext_overlap is not None and ext_overlap.overlaps(iroute):
                if ext_overlap.prefixlen > iroute.prefixlen and prefix.prefixlen > iroute.prefixlen:
                    override = True

            if iroute == prefix:
                # The requested route already exists
                return False
            elif iroute.overlaps(prefix) is False:
                # No overlap, skipping to next internal route
                continue
            elif iroute.overlaps(prefix):
                # Overlap found, compare prefixes
                if iroute.prefixlen < prefix.prefixlen and override is False:
                    # Internal aggregate route already covers the requested route
                    return False
                elif iroute.prefixlen < prefix.prefixlen and override is True:
                    # Existing external route is more specific than existing internal route. Exception needed.
                    return True
                elif iroute.prefixlen > prefix.prefixlen:
                    # Existing internal route is more specific than requested route
                    # Existing, more specific route should be deleted once broader aggregate route is added
                    return True
        # No overlaps were found; The route can be added
        return True

    def eroute_compare(int_overlap=None):
        for eroute in ext_routes:
            override = False
            # Check for internal aggregate routes that may already cover the requested route
            eroute = network(eroute, strict=False)

            if int_overlap is not None and int_overlap.overlaps(eroute):
                if int_overlap.prefixlen > eroute.prefixlen and prefix.prefixlen > eroute.prefixlen:
                    override = True

            if eroute == prefix:
                # The requested route already exists
                return False
            elif eroute.overlaps(prefix) is False:
                # No overlap; Skipping to next prefix
                continue
            elif eroute.overlaps(prefix):
                if eroute.prefixlen < prefix.prefixlen and override is False:
                    # External aggregate route already covers this route
                    return False
                elif eroute.prefixlen < prefix.prefixlen and override is True:
                    # External aggregate route already covers this route
                    return True
                elif eroute.prefixlen > prefix.prefixlen:
                    # Existing external route is more specific than requested route
                    # Existing, more specific route should be deleted once broader aggregate route is added
                    return True
        # This process invoked by internal/external overlap.
        # No external overlaps were found in external table
        return True

    if gateway == 'internal_gateway':
        # Check for aggregate external routes that overlap more specific internal request
        # Default route will always overlap so this logic assumes an overlap will exists even if not by a less specific
        # route
        for route in ext_routes:
            route = network(route, strict=False)

            if route == prefix:
                # This internal route would conflict with an external route.  Reject.
                return False
            elif route.overlaps(prefix):
                # External aggregate route exists; Internal exception route may be required.
                return iroute_compare(ext_overlap=route)
            else:
                # No aggregate overlap found; account for default route
                return iroute_compare()

    if gateway == 'external_gateway':
        # Check for aggregate internal routes that overlap
        for route in int_routes:
            route = network(route, strict=False)

            if route == prefix:
                # This external route would conflict with an internal route. Reject
                return False
            elif route.overlaps(prefix):
                # Internal aggregate route exists; External exception route may be required.
                return eroute_compare(int_overlap=route)

        # No internal overlaps found. Route covered by default.  Reject
        print('Default logic applied')
        return False


def optimize_routes():
    api = GithubAPI()
    file_content = api.get_file_content(file_path='wsa/wsa_routes.xml')

    table = ElementTree.fromstring(file_content)

    routes = table.find('routing_table/[routing_table_interface="Data"]/routes')

    int_routes = routes.findall('route/[gateway="internal_gateway"]/destination')
    ext_routes = routes.findall('route/[gateway="external_gateway"]/destination')

    int_routes = list(route.text for route in int_routes)
    ext_routes = list(route.text for route in ext_routes)

    int_routes.sort()
    ext_routes.sort()

    ext_exceptions = []
    int_exceptions = []

    orig_table_size = len(int_routes) + len(ext_routes)

    # Find network overlaps between internal and external routes
    for iroute in int_routes:
        for xroute in ext_routes:
            in_route = network(iroute, strict=False)
            ex_route = network(xroute, strict=False)

            if in_route.overlaps(ex_route):
                # print(f'Internal route: {iroute} overlaps External route: {xroute}')

                # Create an exception for the smaller network that overlaps
                if ex_route.prefixlen > in_route.prefixlen:
                    ext_exceptions.append(xroute)
                else:
                    int_exceptions.append(iroute)

    # Find network overlaps between internal exceptions
    r2_temp = int_exceptions[:]
    for r1 in int_exceptions[:]:
        n1 = network(r1, strict=False)
        for r2 in r2_temp[r2_temp.index(r1) + 1:]:
            n2 = network(r2, strict=False)
            # Do not compare if networks match
            if n1 == n2:
                continue
            if n1.overlaps(n2):
                # Remove smaller network from exceptions list
                if n1.prefixlen > n2.prefixlen:
                    try:
                        int_exceptions.remove(r1)
                    except ValueError:
                        pass
                else:
                    try:
                        int_exceptions.remove(r2)
                    except ValueError:
                        pass

    # Find network overlaps between external exceptions
    r2_temp = ext_exceptions[:]
    for r1 in ext_exceptions[:]:
        n1 = network(r1, strict=False)
        for r2 in r2_temp[r2_temp.index(r1) + 1:]:
            n2 = network(r2, strict=False)
            # Do not compare if networks match
            if n1 == n2:
                continue
            if n1.overlaps(n2):
                # Remove smaller network from exceptions list
                if n1.prefixlen > n2.prefixlen:
                    try:
                        ext_exceptions.remove(r1)
                    except ValueError:
                        pass
                else:
                    try:
                        ext_exceptions.remove(r2)
                    except ValueError:
                        pass

    # Find overlaps in internal routes
    r2_temp = int_routes[:]
    for r1 in int_routes[:]:
        n1 = network(r1, strict=False)
        for r2 in r2_temp[r2_temp.index(r1) + 1:]:
            n2 = network(r2, strict=False)
            # Do not compare if networks match
            if n1 == n2:
                continue
            if n1.overlaps(n2):
                # Remove smaller network from routing table
                if n1.prefixlen > n2.prefixlen:
                    if r1 not in int_exceptions:
                        try:
                            int_routes.remove(r1)
                        except ValueError:
                            pass
                else:
                    if r2 not in int_exceptions:
                        try:
                            int_routes.remove(r2)
                        except ValueError:
                            pass

    # Insert default route into comparison
    ext_routes.append('0.0.0.0/0')

    # Find overlaps in external routes
    r2_temp = ext_routes[:]
    for r1 in ext_routes[:]:
        n1 = network(r1, strict=False)
        for r2 in r2_temp[r2_temp.index(r1) + 1:]:
            n2 = network(r2, strict=False)
            # Do not compare if networks match
            if n1 == n2:
                continue
            if n1.overlaps(n2):
                # Remove smaller network from routing table
                # print(f'{r1} overlaps {r2}')
                if n1.prefixlen > n2.prefixlen:
                    if r1 not in ext_exceptions:
                        try:
                            ext_routes.remove(r1)
                        except ValueError:
                            pass
                else:
                    if r2 not in ext_exceptions:
                        try:
                            ext_routes.remove(r2)
                        except ValueError:
                            pass

    # Remove default route from external routing table
    ext_routes.remove('0.0.0.0/0')

    new_table_size = len(int_routes) + len(ext_routes)
    difference = orig_table_size - new_table_size

    # Here I need to figure out how I'm going to replace the Gitlab wsa_routes.xml file

    del_routes = routes.findall('route')
    for route in del_routes:
        routes.remove(route)

    route_name = (x for x in range(101, 10000000000, 1))

    for route in int_routes:
        dest = network(route, strict=False)

        route = ElementTree.fromstring(f"""
            <route>
            <route_name>{route_name.__next__()}</route_name>
            <destination>{dest.with_prefixlen}</destination>
            <gateway>internal_gateway</gateway>
            </route>
            """)

        routes.append(route)

    for route in ext_routes:
        dest = network(route, strict=False)

        route = ElementTree.fromstring(f"""
            <route>
            <route_name>{route_name.__next__()}</route_name>
            <destination>{dest.with_prefixlen}</destination>
            <gateway>external_gateway</gateway>
            </route>
            """)

        routes.append(route)

    api.update_file(file_path='wsa/wsa_routes.xml', message='Optimzied Routes', content=ElementTree.tostring(table))

    return f'Process has eliminated {difference} routes.  Original: {orig_table_size} - Revised: {new_table_size}'
