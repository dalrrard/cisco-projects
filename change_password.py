#! python3

import paramiko
from paramiko_expect import SSHClientInteraction
import threading
import time
import sys
import socket
import csv
import getpass

connection = []
output_file = '{}_password_change.txt'.format(int(time.time()))

def get_hosts(filepath):
    with open(filepath, newline='') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in csvreader:
            if len(row[0].split()) > 1 or "\"" in row[0] or "\'" in row[0]:
                print("ABORT: CSV file incorrectly formatted. List only one server per line.")
                sys.exit(0)
            connection.append(row[0])

def session(host, username, password, new_password):
    status = ""
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(host, username=username, password=password)
        interact = SSHClientInteraction(ssh, timeout=60, display=False)
        
        try:
            interact.expect('admin:')
            interact.send('set password user admin')
            interact.expect("Please enter the old password: ")
            interact.send(password)
            interact.expect("   Please enter the new password: ")
            interact.send(new_password)
            interact.expect("Reenter new password to confirm: ", timeout=5)
            interact.send(new_password)
            interact.expect("Password updated successfully.", timeout=20)
            status = "Success!"
        except (paramiko.buffered_pipe.PipeTimeout, socket.timeout) as e:
            status = "Failed!"
            ssh.close()
            sys.exit(0)
            
    except ConnectionResetError as e:
        status = "Failed to connect"
        sys.exit(0)
    except paramiko.ssh_exception.AuthenticationException as e:
        status = "Failed to authenticate"
        sys.exit(0)
    finally:
        with open(output_file, 'a') as out:
            out.write('{} - {}\n'.format(host, status))
            print('{} - {}'.format(host, status))
        ssh.close()
        
def help_me():
    print('Given a csv file of CUCM/CUIC server names or ip addresses, ' \
          'changes Administrator password for listed servers. ' \
          'Displays this info on the screen and saves a file with the information.' \
          'List one server name or ip address per line with no quotes.\n')
    print('Usage: change_password.exe <csv location>')
    sys.exit(0)

def main():
    
    if len(sys.argv) == 1 or sys.argv[1] == '--help' or sys.argv[1] == '/?':
        help_me()
    
    try:
        get_hosts(sys.argv[1])
    except FileNotFoundError as e:
        print("ABORT: CSV file not found. Please enter valid path to file.")
        sys.exit(0)
      
    old_password = getpass.getpass(prompt='Old Password: ', stream=None)
    
    while True:
        new_password = getpass.getpass(prompt='New Password: ', stream=None)
        confirm_password = getpass.getpass(prompt='Confirm New Password: ', stream=None)
        if new_password == confirm_password:
            break
        print("Passwords do not match. ")
    

    print('\nPlease wait...\n')
    
    for i in connection:
        t = threading.Thread(target = session, args = (i, \
                                                       "Administrator", \
                                                       old_password, \
                                                       new_password))
        t.start()


if __name__ == "__main__": main()