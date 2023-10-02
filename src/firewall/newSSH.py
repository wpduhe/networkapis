import paramiko
import sys, ast


class sshSession:
    ssh = paramiko.SSHClient()

    def __init__(self, host_ip, uname, passwd):
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(host_ip, username=uname, password=passwd)
            self.shell = self.ssh.invoke_shell()
        except (paramiko.BadHostKeyException, paramiko.AuthenticationException, paramiko.SSHException) as e:
            print(str(e))
            sys.exit(-1)

    def executeCmd(self, cmd):
        if isinstance(cmd, list):
            out_put = []
            for command in cmd:
                print(command)
                stdin, stdout, stderr = self.ssh.exec_command(command)
                out_put.append(stdout.readlines())
                print(stdout.readlines())
            return out_put
        else:
            try:
                stdin, stdout, stderr = self.ssh.exec_command(cmd)
                out_put = stdout.readlines()
                # for item in out_put:
                #     print(item),
                return out_put
            except paramiko.SSHException as e:
                print(str(e))
                sys.exit(-1)

    def configure(self, commands):
        try:
            for command in commands:
                print(command)
                resp = self.shell.send(command + '\n')
                print(resp)
            return 'Commands executed'
        except:
            return 'Attempt to configure failed'
