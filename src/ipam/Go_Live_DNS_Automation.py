import socket
import re
import requests
import warnings
import json

warnings.filterwarnings("ignore")


URL = "https://proteus-qol.medcity.net"

# BAM Functions

# Get Token for login


def bam_gettoken():

    response_login = requests.get(f"{URL}/Services/REST/v1/login?username=ProteusAPI&password=Z0neF1le", verify=False)
    token = response_login.json().split(' ')[3]
    return token


# Get Config ID from IP
def bam_getIDbyIP(record_var,token_var):

    HCA_InternalID = "3014714"
    response_IP = requests.get(f"{URL}/Services/REST/v1/getIP4Address?containerId={HCA_InternalID}&address="
                               f"{record_var}", headers={'Authorization': f'BAMAuthToken: {token_var}'}, verify=False)
    response_IP_json = response_IP.json()
    IP_ID = response_IP_json["id"]
    return IP_ID


def bam_getIDbyCNAME(CNAME_entry,token_var):

    CNAME_reg = re.match(".+?(?=\.colhca\.com)", CNAME_entry)
    CNAME_name = CNAME_reg.group(0)
    colhca_ID = "42608239"
    response_CNAME_name = requests.get(f"{URL}/Services/REST/v1/getEntityByName?parentId={colhca_ID}&name="
                                       f"{CNAME_name}&type=AliasRecord",
                                       headers={'Authorization': f'BAMAuthToken: {token_var}'}, verify=False)
    response_CNAME_name_json = response_CNAME_name.json()
    CNAME_ID = response_CNAME_name_json["id"]
    return CNAME_ID


# function checks to make sure A records are equivalent count to CNAMEs

def len_ex(mylist, char_number):
    count = 0
    for i in mylist:
        if len(i) > char_number:
            count += 1
    return count

# verify_a validates A record


def verify_a(records: list):
    print("\nVerifying A records...\n")
    failures = 0
    Final_A_Record_List = []

    for record in records:
        record = record.lower()

        if record == "":
            continue
        # If entry is IP address, this pulls all host records associated with IP

        if re.match('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', record):

            print(f"You entered an IP address for an A Record. Performing lookup on A Records associated"
                  f" with {record}\n")
            print(record)
            # Config ID

            # login and get token
            token = bam_gettoken()

            # Use token to query the IP to get the Config ID
            IP_ID = bam_getIDbyIP(record, token)

            # Use the config ID to pull A records associated with the IP
            response_A_Record = requests.get(f"{URL}/Services/REST/v1/getLinkedEntities?entityId={IP_ID}&type="
                                             f"HostRecord&start=0&count=10000",
                                             headers={'Authorization': f'BAMAuthToken: {token}'}, verify=False)
            response_A_Record_json = response_A_Record.json()

            # Pulls out the A Record from the API request & verifying that only 1 unix record comes up,
            # if not then error
            unix_names = 0

            for dct in response_A_Record_json:

                dct_prop = dct['properties']
                newdct = dict([x.split('=') for x in dct_prop.split('|') if x])
                #print(newdict['absoluteName'])
                abs_name = newdct['absoluteName']

                if re.match(".*\.unix\.medcity\.net", abs_name):
                    unix_names += 1
                    Final_A_Record_List.append(abs_name)
                    print(f"Found record {abs_name} linked to {record}\n")

            # Checking if there are mutlple unix records or none at all, if so, throws printed error
            if unix_names > 1:
                print(f'FAIL - {record} has multiple unix.medcity.net Records. User must sp'
                      f'ecify which record. Please, contact Chris Moses for assistance')
                failures += 1

            elif unix_names < 1:
                print(f'FAIL - {record} has no unix.medcity.net Records associated. Please, contact Chris Moses.\n')
                failures += 1

        elif not re.match('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', record):
            print(record)
            try:
                lookup = socket.gethostbyname_ex(record)

                if record == lookup[0]:
                    print(f'SUCCESS - A RECORD: {record} {lookup}\n')
                    Final_A_Record_List.append(record)
                else:
                    print(f"The entry you entered: {record} is actually a CNAME pointing to {lookup[0]}. \n"
                          f"Therefore, {lookup[0]} will be used as the A record entry.\n")
                    Final_A_Record_List.append(lookup[0])
            except:
                print(f'FAIL - A RECORD: {record} is INVALID\n')
                failures += 1
        else:
            print("A RECORD ENTRY IS INVALID")
    if failures > 0:
        raise ValueError("PLEASE, VERIFY A RECORDS")
    return Final_A_Record_List


# verify_cname validates CNAME record is not typo'd

def re_check_c(cname):
    if re.match('^\s*((?:mmdu|mmdu-t|gw|cl|)\.\d{5}\.colhca\.com)[.]{0,1}\s*$', cname.lower()) is not None:
        print(f"{cname}: is valid")
        return True
    else:
        return False


def verify_c(cnames: str):
    print("Verifying CNAMEs....\n")
    if not re_check_c(cnames):
        raise ValueError(f"{cnames} is NOT VALID! Please, correct and try again.")


# API call to create CNAMEs

def bam_create_cnames_by_list(cname_list, a_list):
    token = bam_gettoken()
    dns_view = "8561989"
    newlist = list(zip(cname_list, a_list))
    for pair in newlist:
        # pair0 is the CNAME, pair1 is the A record
        print(f'Creating: {pair[0]} -> {pair[1]}')
        response_status = requests.post(f"{URL}/Services/REST/v1/addAliasRecord?viewId={dns_view}&absoluteName="
                                        f"{pair[0]}&linkedRecordName={pair[1]}&ttl=-1&properties=parentZoneName="
                                        f"colhca.com|linkedParentZoneName=unix.medcity.net",
                                        headers={'Authorization': f'BAMAuthToken: {token}'}, verify=False)
        #
        #
        #
        #
        #
        # if response_status.json() == "Duplicate of another item":
        #     lookup = socket.gethostbyname_ex(pair[0])
        #     if pair[1] != lookup[0]:
        #         prompt = input(f"WARNING: The CNAME {pair[0]} is already pointing to a different A record: "
        #                        f"{lookup[0]}. Would you like to overwrite this? Yes or No")
        #         if prompt == "Yes":
        #             # update CNAME
        #             CNAME_ID, CNAME_name = bam_getIDbyCNAME(pair[0], token)
        #             bam_update_CNAME(CNAME_name, pair[1], CNAME_ID)
        #         elif prompt == "No":
        #             print("\nSkipping CNAME..\n")
        #
        #         else:
        #             print("Invalid input, skipping to next CNAME")
        #
        #     else:
        #         print(f'NOTIFICATION: {pair[0]} is {response_status.json()}. Skipping to next CNAME...\n')
        #
        #
        #
        #
        #

# Next 2 functions update an existing CNAME record if the entry already exists
def bam_getIDbyCNAME(CNAME_entry,token_var):

    CNAME_reg = re.match(".+?(?=\.colhca\.com)", CNAME_entry)
    CNAME_name = CNAME_reg.group(0)
    colhca_ID = "42608239"
    response_CNAME_name = requests.get(f"{URL}/Services/REST/v1/getEntityByName?parentId={colhca_ID}&name={CNAME_name}"
                                       f"&type=AliasRecord",
                                       headers={'Authorization': f'BAMAuthToken: {token_var}'}, verify=False)
    response_CNAME_name_json = response_CNAME_name.json()
    CNAME_ID = response_CNAME_name_json["id"]
    return CNAME_ID, CNAME_name


def bam_update_CNAME(CNAME_name, linkedRecord, CNAME_ID):
    token = bam_gettoken()
    payload = {"id": f'{CNAME_ID}', "name": f'{CNAME_name}', "type": "AliasRecord",
               "properties": f"linkedRecordName={linkedRecord}|"}
    print(linkedRecord)
    print(f'ID: {CNAME_ID}')
    print(f'CNAME name: {CNAME_name}')
    print(token)
    response = requests.put(f"{URL}/Services/REST/v1/update?id={CNAME_ID}", data=json.dumps(payload),
                            headers={'Authorization': f'BAMAuthToken: {token}', 'Content-Type': "application/json"},
                            verify=False)
    print(f'this is response: {response}')


# Calling functions

def create(req_data: dict):
    cnames = req_data['CNames']
    arecords = req_data['ARecords']

    print(cnames)
    print(arecords)

    Final_CNAME_records = []

    for c in cnames:
        if c is "":
            continue
        else:
            Final_CNAME_records.append(c.lower())

    print(Final_CNAME_records)

    for x in Final_CNAME_records:
        if x == "":
            continue
        try:
            verify_c(x)
        except ValueError:
            return 400, [f'Cname is invalid: {x}']

    Final_A_Records = verify_a(arecords)

    # this verifies that there are equal number of C -> A
    count_A = len_ex(Final_A_Records, 0)
    count_C = len_ex(Final_CNAME_records, 0)

    if count_A != count_C:
        return 400, ['ValueError: Uneven entry. Please, specify a CNAME for every A Record and vice versa.']

    # function makes API to create CNAMEs
    bam_create_cnames_by_list(Final_CNAME_records, Final_A_Records)

    return 200, ['Reqeust Completed Successfully']
