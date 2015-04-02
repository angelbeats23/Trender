#!/usr/bin/python2.7
from controller import Controller
import sys
import signal

# create the thread object
controller = Controller()

# spawn a new thread
controller.start()


def main():
    while True:
        cmd = raw_input("> ")
        if cmd == "status":
            # you can add extra functions to thread to do what you need
            controller.status()
        else:
            print"unknown command"


def signal_handler(signal, frame):
        flag = controller.get_flag()
        while not flag:
            pass
        print '\nExit Program Safely'
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":

    # Call the main function
    main()