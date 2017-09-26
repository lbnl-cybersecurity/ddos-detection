import pyinotify

class MyEventHandler(pyinotify.ProcessEvent):
    def process_IN_CLOSE_WRITE(self, event):
        print "CLOSE_WRITE event:", event.pathname


def main():
    # Watch manager
    wm = pyinotify.WatchManager()
    working_dir = '/home/chang/DDoS/dot/tmp'
    wm.add_watch(working_dir, pyinotify.ALL_EVENTS, rec=True)

    # Event handler
    eh = MyEventHandler()

    # Notifier
    notifier = pyinotify.Notifier(wm, eh)
    notifier.loop()

if __name__ == '__main__':
    main()

