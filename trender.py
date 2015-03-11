from mainthread import MainThread
import sys
import signal

# create the thread object
m_thread = MainThread()

# spawn a new thread
m_thread.start()


def main():
    while True:
        cmd = raw_input("> ")
        if cmd == "status":
            # you can add extra functions to thread to do what you need
            m_thread.status()
        else:
            print"unknown command"


def signal_handler(signal, frame):
        flag = m_thread.get_flag()
        while not flag:
            pass
        print '\nExit Program Safely'
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":

    # Call the main function
    main()