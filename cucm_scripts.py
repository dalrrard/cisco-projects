# -*- coding: utf-8 -*-
"""
Created on Mon Oct  9 11:32:14 2017

@author: DRARDIN
"""

import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
from tkinter import messagebox as msg
import tkinter.scrolledtext as tkst
import paramiko
from paramiko_expect import SSHClientInteraction
import threading
import time
import sys
import socket
import csv
import re


# IORedirector and StdoutRedirector alter the print function to write to
# tkinter window
class IORedirector(object):

    def __init__(self, text_area):
        self.text_area = text_area


class StdoutRedirector(IORedirector):

    def write(self, str):
        self.text_area.insert("end", str)

    def flush(self):
        pass


class Root(tk.Tk):

    # Create main window with file browser and options
    def __init__(self):
        super().__init__()
        self.csv_file = tk.StringVar()
        self.uname = tk.StringVar()
        self.password = tk.StringVar()
        self.new_password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        self.new_user = tk.StringVar()
        self.privilege_level = tk.StringVar()
        self.create_password = tk.StringVar()
        self.delete_username = tk.StringVar()
        self.connections = []
        self.output_file = '{}.txt'.format(int(time.time()))

        self.title("Telecom Scripts")

        mainframe = ttk.Frame(self, padding="3 3 12 12")
        mainframe.grid(column=0, row=0, sticky=(tk.N, tk.W, tk.E, tk.S))
        mainframe.columnconfigure(0, weight=1)
        mainframe.rowconfigure(0, weight=1)

        self.info1 = ttk.Label(mainframe, text="Browse to the location of a CSV "
                              "file formatted with one server name or IP ").grid(column=2, row=1, columnspan=3)
        self.info2 = ttk.Label(mainframe, text="address per line then click any button to run "
                               "that command on all listed servers").grid(column=2, row=2, columnspan=3)

        ttk.Button(mainframe, text="Browse...", command=lambda: self.csv_file.set(
            filedialog.askopenfilename())).grid(column=1, row=3, sticky=tk.E)
        file_name = ttk.Entry(mainframe, width=90, textvariable=self.csv_file)
        file_name.grid(column=2, row=3, columnspan=4)

        ttk.Button(mainframe, text="Change Password",
                   command=lambda: self.password_window(0)).grid(column=1, row=4)
        ttk.Button(mainframe, text="Monitor IMP",
                   command=lambda: self.password_window(1)).grid(column=2, row=4)
        ttk.Button(mainframe, text="Shutdown Servers",
                   command=lambda: self.password_window(2)).grid(column=3, row=4)
        ttk.Button(mainframe, text="Create User",
                   command=lambda: self.password_window(3)).grid(column=4, row=4)
        ttk.Button(mainframe, text="Delete User",
                   command=lambda: self.password_window(4)).grid(column=5, row=4)
        ttk.Button(mainframe, text="Show Disk Usage",
                   command=lambda: self.password_window(5)).grid(column=6, row=4)

        for child in mainframe.winfo_children():
            child.grid_configure(padx=5, pady=5)

        file_name.focus()

    # Create password window with additional arguments for change password
    # function
    def password_window(self, x):
        self.pw_root = tk.Toplevel(self)
        self.pw_root.title("Enter credentials")

        self.name = ttk.Entry(self.pw_root, textvariable=self.uname)
        self.pw = ttk.Entry(self.pw_root, textvariable=self.password, show='*')

        ttk.Label(self.pw_root, text="Username").grid(column=1, row=1)

        # Display different fields in password window for different functions
        if x == 0:
            self.name.grid(column=2, row=1)
            self.pw.grid(column=2, row=2)
            self.new_pw = ttk.Entry(
                self.pw_root, textvariable=self.new_password, show='*').grid(column=2, row=3)
            self.confirm_pw = ttk.Entry(
                self.pw_root, textvariable=self.confirm_password, show='*').grid(column=2, row=4)
            ttk.Label(self.pw_root, text="Old Password").grid(column=1, row=2)
            ttk.Label(self.pw_root, text="New Password").grid(column=1, row=3)
            ttk.Label(self.pw_root, text="Confirm Password").grid(
                column=1, row=4)
        elif x == 3:
            self.name.grid(column=2, row=1, columnspan=2)
            self.pw.grid(column=2, row=2, columnspan=2)
            self.new_uname = ttk.Entry(self.pw_root, textvariable=self.new_user).grid(
                column=2, row=3, columnspan=2)
            self.new_pw = ttk.Entry(
                self.pw_root, textvariable=self.create_password, show='*').grid(column=2, row=4, columnspan=2)
            self.confirm_pw = ttk.Entry(
                self.pw_root, textvariable=self.confirm_password, show='*').grid(column=2, row=5, columnspan=2)
            ttk.Radiobutton(self.pw_root, text="0", variable=self.privilege_level, value=0).grid(
                column=2, row=6)
            ttk.Radiobutton(self.pw_root, text="1", variable=self.privilege_level, value=1).grid(
                column=3, row=6)
            ttk.Label(self.pw_root, text="Password").grid(column=1, row=2)
            ttk.Label(self.pw_root, text="New Username").grid(column=1, row=3)
            ttk.Label(self.pw_root, text="New Password").grid(column=1, row=4)
            ttk.Label(self.pw_root, text="Confirm Password").grid(
                column=1, row=5)
            ttk.Label(self.pw_root, text="Privilege Level").grid(
                column=1, row=6)
        elif x == 4:
            self.name.grid(column=2, row=1)
            self.pw.grid(column=2, row=2)
            self.del_uname = ttk.Entry(
                self.pw_root, textvariable=self.delete_username).grid(column=2, row=3)
            ttk.Label(self.pw_root, text="Password").grid(column=1, row=2)
            ttk.Label(self.pw_root, text="Username for deletion").grid(
                column=1, row=3)
        else:
            self.name.grid(column=2, row=1, columnspan=2)
            self.pw.grid(column=2, row=2, columnspan=2)
            ttk.Label(self.pw_root, text="Password").grid(column=1, row=2)

        # Dictionary to correctly place Ok button in password windows with
        # different amount of options
        ok_grid = {0: 5,
                   3: 7,
                   4: 4}

        ttk.Button(self.pw_root, text="Ok", command=lambda: self.redirector(
            window=x)).grid(column=2, row=ok_grid.get(x, 3), sticky=tk.W)
        self.pw_root.bind("<Return>", lambda _: self.redirector(window=x))

        for child in self.pw_root.winfo_children():
            child.grid_configure(padx=5, pady=5)

        self.name.focus()

    # Redirect sys.stdout to text box. Get contents of csv and start threads.
    # Need to break this apart. Doing too many things.
    def redirector(self, window, inputStr=""):
        self.display_root = tk.Toplevel()
        text = tkst.ScrolledText(self.display_root)
        sys.stdout = StdoutRedirector(text)
        text.pack()
        text.insert(tk.END, inputStr)
        try:
            # Verify that user is typing new password correctly for options
            # that require a new password or password change
            if window == 0 and self.new_password.get() != self.confirm_password.get():
                raise
            elif window == 3 and self.create_password.get() != self.confirm_password.get():
                raise
            self.get_hosts(self.csv_file.get())

            # Read from csv file of servers and start thread for each
            for i in self.connections:
                t = threading.Thread(target=self.session, args=(window, i,
                                                                self.uname.get(),
                                                                self.password.get()))
                t.setDaemon(True)
                t.start()
        except RuntimeError:
            msg.showerror(
                "ABORT", "Password and confirm password do not match.")
            self.display_root.destroy()
        except FileNotFoundError as e:
            msg.showerror(
                "ABORT", "CSV file not found. Please enter valid path to file.")
            self.display_root.destroy()
        finally:
            # Remove servers from list after to prevent the list from
            # duplicating if more than one operation is done
            for i in self.connections:
                del i
            self.pw_root.destroy()
            # Start thread to check if all other threads are complete
            t = threading.Thread(target=self.check_threads)
            t.setDaemon(True)
            t.start()

    # Gets list of hosts from csv file. Makes sure that file is correctly
    # formatted.
    def get_hosts(self, filepath):
        try:
            with open(filepath, newline='') as csvfile:
                csvreader = csv.reader(csvfile, delimiter=',', quotechar='|')
                for row in csvreader:
                    # Check for incorret formatting in CSV
                    if len(row[0].split()) > 1 or "\"" in row[0] or "\'" in row[0]:
                        raise
                    self.connections.append(row[0])
        except RuntimeError:
            msg.showerror(
                "ABORT", "CSV file incorrectly formatted. List only one server per line.")

    # Start ssh session to server. Removes hosts from list after running
    # to prevent duplication in list if program is run twice.
    def session(self, window, host, username, password):
        status = ""
        output = ""

        try:
            # Connect to server and run whichever function the user requested
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password)

            if window == 0:
                self.change_password(ssh, host, status, output)
            elif window == 1:
                self.imp_status(ssh, host, status, output)
            elif window == 2:
                self.shutdown_cucm(ssh, host, status, output)
            elif window == 3:
                self.create_user(ssh, host, status, output)
            elif window == 4:
                self.delete_user(ssh, host, status, output)
            elif window == 5:
                self.show_disk(ssh, host, status, output)
        except ConnectionResetError as e:
            status = "Failed to connect - {}".format(host)
            ssh.close()
            with open(self.output_file, 'a') as out:
                out.write('{} - {}\n'.format(host, status))
                out.write(output)
                print('{} - {}'.format(host, status))
                print(output)
            ssh.close()
            msg.showerror("ABORT", status)
            return
        except paramiko.ssh_exception.AuthenticationException as e:
            status = "{} - Failed to authenticate".format(host)
            with open(self.output_file, 'a') as out:
                out.write('{}\n'.format(status))
                out.write(output)
                print('{}'.format(status))
                print(output)
            ssh.close()
            msg.showerror("Failed to authenticate",
                          "Please enter correct username and password for {}.".format(host))
            return
        finally:
            self.connections.remove(host)

    # Sends commands to shutdown call manager.
    def shutdown_cucm(self, ssh, host, status, output):
        try:
            interact = SSHClientInteraction(ssh, timeout=600, display=True)
            print("{} - connected and working".format(host))

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
                msg.showerror("ABORT", "{} - {}".format(status, host))
                return
        finally:
            with open(self.output_file, 'a') as out:
                out.write('{} - {}\n'.format(host, status))
                out.write(output)
                print('{} - {}'.format(host, status))
                print(output)
            ssh.close()
            return

    # Sends commands to change password on call manager.
    def change_password(self, ssh, host, status, output):
        try:
            interact = SSHClientInteraction(ssh, timeout=60, display=False)
            print("{} - connected and working".format(host))

            try:
                interact.expect('admin:')
                interact.send('set password user admin')
                interact.expect("Please enter the old password: ")
                interact.send(self.password.get())
                interact.expect("   Please enter the new password: ")
                interact.send(self.new_password.get())
                interact.expect("Reenter new password to confirm: ", timeout=5)
                interact.send(self.new_password.get())
                interact.expect("Password updated successfully.", timeout=20)
                status = "Success!"
            except (paramiko.buffered_pipe.PipeTimeout, socket.timeout) as e:
                status = "Failed!"
                ssh.close()
                msg.showerror("ABORT", "{} - {}".format(status, host))
                return
        finally:
            with open(self.output_file, 'a') as out:
                out.write('{} - {}\n'.format(host, status))
                print('{} - {}'.format(host, status))
            ssh.close()
            return

    # Sends commands to check IMP status on call manager.
    def imp_status(self, ssh, host, status, output):
        try:
            interact = SSHClientInteraction(ssh, timeout=60, display=False)
            print("{} - connected and working".format(host))

            try:
                interact.expect('admin:')
                interact.send('run sql select name, isprimary, '
                              'case '
                              'when tkhaserverstate = 2 then "idle" '
                              'when tkhaserverstate = 3 then "normal" '
                              'when tkhaserverstate = 4 then "backup" '
                              'else to_char(tkhaserverstate) '
                              'end as tkhaserverstate from enterprisenode')
                interact.expect('admin:')
                output = interact.current_output_clean
                interact.send(
                    'run sql select name, haenabled from enterprisesubcluster')
                interact.expect('admin:')
                output += '\n' + interact.current_output_clean
                status = "Success!"
            except (paramiko.buffered_pipe.PipeTimeout, socket.timeout) as e:
                status = "Failed!"
                ssh.close()
                msg.showerror("ABORT", "{} - {}".format(status, host))
                return
        finally:
            with open(self.output_file, 'a') as out:
                out.write('{} - {}\n'.format(host, status))
                out.write(output)
                print('{} - {}'.format(host, status))
                print(output)
            ssh.close()
            return

    # Sends commands to create user with specified privilege level on call
    # manager.
    def create_user(self, ssh, host, status, output):
        try:
            interact = SSHClientInteraction(ssh, timeout=60, display=False)
            print("{} - connected and working".format(host))

            try:
                interact.expect('admin:')
                interact.send('set account name ' + self.new_user.get())
                interact.expect("Please enter the privilege level :")
                interact.send(self.privilege_level.get())
                interact.expect("       Please enter the password :")
                interact.send(self.create_password.get())
                interact.expect("             re-enter to confirm :")
                interact.send(self.create_password.get())
                interact.expect("admin:")
                output = interact.current_output_clean
                status = "Complete. Check logs for status!"
            except (paramiko.buffered_pipe.PipeTimeout, socket.timeout) as e:
                status = "Failed!"
                ssh.close()
                msg.showerror("ABORT", "{} - {}".format(status, host))
                return
        finally:
            with open(self.output_file, 'a') as out:
                out.write('{} - {}\n'.format(host, status))
                out.write(output)
                print('{} - {}'.format(host, status))
                print(output)
            ssh.close()
            return

    # Sends commands to delete user on call manager.
    def delete_user(self, ssh, host, status, output):
        try:
            interact = SSHClientInteraction(ssh, timeout=60, display=False)
            print("{} - connected and working".format(host))

            try:
                interact.expect('admin:')
                interact.send('delete account ' + self.delete_username.get())
                interact.expect("admin:")
                output = interact.current_output_clean
                status = "Complete."
            except (paramiko.buffered_pipe.PipeTimeout, socket.timeout) as e:
                status = "Failed!"
                ssh.close()
                msg.showerror("ABORT", "{} - {}".format(status, host))
                return
        finally:
            with open(self.output_file, 'a') as out:
                out.write('{} - {}\n'.format(host, status))
                out.write(output)
                print('{} - {}'.format(host, status))
                print(output)
            ssh.close()
            return

    # Sends command to show status and regex to display disk usage.
    def show_disk(self, ssh, host, status, output):

        disk_regex = re.compile(r'[\s]+Total[\s]+Free[\s]+Used[\s\S]+$')

        try:
            interact = SSHClientInteraction(ssh, timeout=60, display=False)
            print("{} - connected and working".format(host))

            try:
                interact.expect('admin:')
                interact.send('show status')
                interact.expect("admin:")
                output = interact.current_output_clean
                reg_output = disk_regex.search(output)
                status = "Complete."
            except (paramiko.buffered_pipe.PipeTimeout, socket.timeout) as e:
                status = "Failed!"
                ssh.close()
                msg.showerror("ABORT", "{} - {}".format(status, host))
                return
            except AttributeError as e:
                print(output)
        finally:
            with open(self.output_file, 'a') as out:
                out.write('{} - {}\n'.format(host, status))
                if reg_output:
                    out.write(reg_output.group())
                else:
                    out.write("Couldn't find information")
                print('{} - {}'.format(host, status))
                if reg_output:
                    print(reg_output.group())
                else:
                    print("Couldn't find information")
            ssh.close()
            return

    # Check if all threads but the main thread and this thread are complete.
    # If they are, give user visual prompt that they're finished.
    def check_threads(self):
        while True:
            if threading.active_count() > 2:
                time.sleep(1)
            else:
                print("DONE!")
                break

if __name__ == "__main__":
    root = Root()
    root.mainloop()
