from nexus.utils import NXOS
import pandas as pd
import re

XRDC_CORE = '10.29.244.56'
FWDC_CORE = '10.90.1.54'


def get_enterprise_route_table() -> pd.DataFrame:
    xrdc_core = NXOS(XRDC_CORE)
    fwdc_core = NXOS(FWDC_CORE)

    xrdc_routes_list = xrdc_core.exec_command('show ip bgp regexp "[0-9]$" | inc /')
    fwdc_routes_list = fwdc_core.exec_command('show ip bgp regexp "[0-9]$" | inc /')

    xrdc_routes_list = xrdc_routes_list.split('\n')
    fwdc_routes_list = fwdc_routes_list.split('\n')

    xr_data = []
    fw_data = []

    for route in xrdc_routes_list:
        prefix = re.search(r'\D+(\S+)', route)
        if not prefix:
            continue
        origin_as = re.search(r'(\d+)\D+$', route)[1]

        data = {
            'Network': prefix[1],
            'Origin_AS': origin_as
        }

        xr_data.append(data)

    for route in fwdc_routes_list:
        prefix = re.search(r'\D+(\S+)', route)
        if not prefix:
            continue
        origin_as = re.search(r'(\d+)\D+$', route)[1]

        data = {
            'Network': prefix[1],
            'Origin_AS': origin_as
        }

        fw_data.append(data)

    x_df = pd.DataFrame(data=xr_data)
    f_df = pd.DataFrame(data=fw_data)

    print(f'XR: {len(x_df)}')
    print(f'FW: {len(f_df)}')

    df = x_df.merge(f_df, how='outer', on='Network')

    df['Origin_AS'] = [None for _ in range(len(df))]

    for index, row in df.iterrows():
        if row['Origin_AS_x'] == row['Origin_AS_y']:
            row['Origin_AS'] = row['Origin_AS_x']
        elif str(row['Origin_AS_x']).isnumeric():
            row['Origin_AS'] = row['Origin_AS_x']
        elif str(row['Origin_AS_y']).isnumeric():
            row['Origin_AS'] = row['Origin_AS_y']
        else:
            continue

    route_index = df.loc[df['Network'] == '0.0.0.0/0']

    df = df.drop(route_index.index)
    print(f'Final: {len(df)}')

    return df
