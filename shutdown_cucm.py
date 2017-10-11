# -*- coding: utf-8 -*-
"""
Created on Thu Oct  5 11:10:16 2017

@author: DRARDIN
"""

import paramiko
from paramiko_expect import SSHClientInteraction
import threading
import time
import sys
import socket
import csv
import getpass

connection = []
output_file = '{}_shutdown.txt'.format(int(time.time()))

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
        interact = SSHClientInteraction(ssh, timeout=600, display=True)
        
        try:
            interact.expect('admin:')
            interact.send('utils system shutdown')
            time.sleep(5)
            interact.send('yes')
            interact.expect('The system is going down for halt NOW!')
            output = interact.current_output_clean
            status = "Success!"
        except (paramiko.buffered_pipe.PipeTimeout, socket.timeout) as e:
            output = interact.current_output_clean
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
          'shuts down the servers. ' \
          'Displays this info on the screen and saves a file with the information.' \
          'List one server name or ip address per line with no quotes.\n')
    print('Usage: shutdown_cucm.exe <csv location>')
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

