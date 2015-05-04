#!/usr/bin/python2.7
from controller import Controller
import sys
import signal

# creates the controller's thread object
controller = Controller()

# spawn a new thread
controller.start()


def main():
    while True:
        cmd = raw_input("> ")
        if cmd == "status":
            # sends a output to the terminal
            # if controller threads has stopped functioning "Thread has stopped"
            # if controller thread is running "Database is being written"
            controller.status()
        else:
            print"unknown command"


def signal_handler(signal, frame):
        # the flag indicates to the signal hander that the controller thread object is
        # ready to close down
        flag = controller.get_flag()
        while not flag:
            pass
        # closes both threads
        print '\nExit Program Safely'
        sys.exit(0)

# Listens for the Ctrl C command to be executed then closes the application
signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":

    # Call the main function
    main()