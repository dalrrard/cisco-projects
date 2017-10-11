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
output_file = '{}_imp.txt'.format(int(time.time()))

def get_hosts(filepath):
    with open(filepath, newline='') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in csvreader:
            if len(row[0].split()) > 1 or "\"" in row[0] or "\'" in row[0]:
                print("ABORT: CSV file incorrectly formatted. " \
                      "List only one server per line.")
                sys.exit(0)
            connection.append(row[0])

def session(host, username, password):
    status = ""
    output = ""
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(host, username=username, password=password)
        interact = SSHClientInteraction(ssh, timeout=60, display=False)
        
        try:
            interact.expect('admin:')
            interact.send('run sql select name, isprimary, ' \
                          'case ' \
                              'when tkhaserverstate = 2 then "idle" ' \
                              'when tkhaserverstate = 3 then "normal" ' \
                              'when tkhaserverstate = 4 then "backup" ' \
                              'else to_char(tkhaserverstate) ' \
                              'end as tkhaserverstate from enterprisenode')
            interact.expect('admin:')
            output = interact.current_output_clean
            interact.send('run sql select name, haenabled from enterprisesubcluster')
            interact.expect('admin:')
            output += '\n' + interact.current_output_clean
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
            out.write(output)
            print('{} - {}'.format(host, status))
            print(output)
        ssh.close()
        
def help_me():
    print('Given a csv file of CUCM/CUIC server names or ip addresses, ' \
          'lists IMP information for servers. ' \
          'Displays this info on the screen and saves a file with the information.' \
          'List one server name or ip address per line with no quotes.\n')
    print('Usage: imp_monitoring.exe <csv location>')
    sys.exit(0)

def main():
    if len(sys.argv) == 1 or sys.argv[1] == '--help' or sys.argv[1] == '/?':
        help_me()
    
    try:
        get_hosts(sys.argv[1])
    except FileNotFoundError as e:
        print("ABORT: CSV file not found. Please enter valid path to file.")
        sys.exit(0)
        
    password = getpass.getpass(prompt='Password: ', stream=None)

    print('\nPlease wait...\n')
    
    for i in connection:
        t = threading.Thread(target = session, args = (i, \
                                                       "Administrator", \
                                                       password))
        t.start()


if __name__ == "__main__": main()