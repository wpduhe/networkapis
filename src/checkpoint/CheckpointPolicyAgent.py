import pathlib
import json
import time
import datetime
from checkpoint.CheckpointUtilities import CheckpointAPI

while True:
    if pathlib.Path(rf'checkpoint/PolicyPushQueue').exists():

        print(f'Checking for pending policy installs.')
        files = pathlib.Path(rf'checkpoint/PolicyPushQueue').glob('*.json')
        
        for policy in files:
            print(f'Found {policy}')
            API = CheckpointAPI()
            API.Domain = policy.name.split('--')[1].split('.')[0]
            API.IPAddress = '10.26.1.96'
            API.SessionDescription = 'PolicyPushAutomation'
            API.SessionName = 'PolicyPushAutomation'
            API.Username = 'corpsvcfwlautomation'

            API.Login()

            URI = '/web_api/v1.3/install-policy'

            JSON = json.loads(policy.read_text())

            InstallAttempt = API.PostJSON(URI,JSON)

            if 200 <= InstallAttempt.status_code < 300:
                # Delete the file since the policy push was successful
                print(f'Policy push for {policy.name} successful')

                print(InstallAttempt.json())

                policy.rename(pathlib.Path(policy.parent, policy.stem + '_InProgress.json'))
                policy = pathlib.Path(policy.parent, policy.stem+"_InProgress.json")

                TaskID = InstallAttempt.json()['task-id']

                # Report on Status
                x = 0
                while x < 300:
                    Status = API.GetTaskStatus(TaskID).json()
                    print(f"Current State as of {datetime.datetime.now().time()}: {Status['tasks'][0]['status']} - "
                          f"{Status['tasks'][0]['progress-percentage']}")
                    currentprogress = f"{Status['tasks'][0]['status']} - {Status['tasks'][0]['progress-percentage']}"
                    policy.write_text(currentprogress)
                    if Status['tasks'][0]['progress-percentage'] == 100:
                        print('Policy Push Complete')
                        policy.unlink()
                        break
                    x += 1
                    time.sleep(30)

                if x == 300:
                    print('Timeout exceeded for policy push')
            else:
                print(f'Attempt unsuccessful...')

            API.Logout()

        print(f'Sleeping for 60 seconds...')
        time.sleep(60)
    else:
        print('Policy install directory was not found.')
        print(f'Sleeping for 60 seconds...')
        time.sleep(60)
