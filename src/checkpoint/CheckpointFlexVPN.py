from checkpoint import CheckpointUtilities


def AddNetworksToFlexVPN(Networks, SessionDescription, SessionName):
    API = CheckpointUtilities.CheckpointAPI()
    API.ReadOnly = False
    API.SessionDescription = SessionDescription
    API.SessionName = SessionName
    API.Domain = 'Colo'
    API.IPAddress = '10.26.1.96'

    API.Login()
    if isinstance(Networks, list):
        for network in Networks:
            API.CreateNetworkObject(f'Flex_{network}', network, 'Blue', SessionName)
            API.SetGroupMembership(f'Flex_{network}', 'Flex-VPN-Spoke-Site', 'Add')
    else:
        # Handle if a single network is passed.
        API.CreateNetworkObject(f'Flex_{Networks}', Networks, 'Blue', SessionName)
        API.SetGroupMembership(f'Flex_{Networks}', 'Flex-VPN-Spoke-Site', 'Add')

    API.PublishChanges()
    API.Logout()

    API.QueuePolicyPush('Colo_Aruba')


def RemoveNetworksFromFlexVPN(Networks, SessionDescription, SessionName):
    API = CheckpointUtilities.CheckpointAPI()
    API.ReadOnly = False
    API.SessionDescription = SessionDescription
    API.SessionName = SessionName
    API.Domain = 'Colo'
    API.IPAddress = '10.26.1.96'

    API.Login()

    if isinstance(Networks, list):
        for network in Networks:
            # Remove the network from the Flex VPN group
            API.SetGroupMembership(f'Flex_{network}', 'Flex-VPN-Spoke-Site', 'Remove')

            # Now let's delete the network from the CMA if it's not used for anything else...
            results = API.SearchObjects(network).json()
            network_object = next(result for result in results['objects'] if result['name'] == f'Flex_{network}')
            usage = API.GetObjectUsage(network_object['uid']).json()

            if usage['used-directly']['total'] == 0 and usage['used-indirectly']['total'] == 0:
                # Delete the object from the CMA since it's not used anywhere else.
                API.DeleteNetworkObject(network)
    else:
        # Remove the network from the Flex VPN group
        API.SetGroupMembership(f'Flex_{Networks}', 'Flex-VPN-Spoke-Site', 'Remove')

        # Now let's delete the network from the CMA if it's not used for anything else...
        results = API.SearchObjects(Networks).json()
        network_object = next(result for result in results['objects'] if result['name'] == f'Flex_{Networks}')
        usage = API.GetObjectUsage(network_object['uid']).json()

        if usage['used-directly']['total'] == 0 and usage['used-indirectly']['total'] == 0:
            # Delete the object from the CMA since it's not used anywhere else.
            API.DeleteNetworkObject(Networks)

    # We're done, let's publish our changes.
    API.PublishChanges()
    API.Logout()

    # Queue Policy Push
    API.QueuePolicyPush('Colo_Aruba')
