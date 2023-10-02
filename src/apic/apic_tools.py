import json


def checkChildTDn(obj: dict, *args):
    # This request takes and an APIC object and searches parent class, for the child class, that matches the tDn name
    # Sample Request checkChildTDn(epg, 'fvAEPg', 'fvRsDomAtt', 'phy-dom-TPDC'
    for child in obj[args[0]]['children']:
        if args[1] in child.keys():
            if args[2] in child[args[1]]['attributes']['tDn']:
                return True
    return False


def intf_range(array):
    interfaces = []
    for y in array[:]:
        if '-' in y:
            y = y.split('-')
            for x in range(int(y[0]), int(y[1]) + 1):
                interfaces.append(x)
        else:
            interfaces.append(int(y))
    return interfaces


def set_of_object_list(array):
    clean_array = []
    new_array = []
    for y in array:
        clean_array.append(json.dumps(y))

    clean_array = list(set(clean_array))

    for x in clean_array:
        new_array.append(json.loads(x))

    return new_array
