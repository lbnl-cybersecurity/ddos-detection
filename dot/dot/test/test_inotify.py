import inotify
import sys

def main():
    working_dir = '/home/chang/DDoS/dot/tmp'
    w = inotify.watcher.AutoWatcher()
    w.add_all(working_dir, inotify.IN_CLOSE_WRITE)

    try:
        while w.num_watches():
            for evt in w.read():
                print evt.fullpath
    except:
        pass

if __name__ == '__main__':
    main()

