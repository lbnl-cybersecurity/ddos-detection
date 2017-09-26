import threading
import time

def worker_one():
    count = 10
    while count > 0:
        #print "Worker one"
        time.sleep(5)
        count -= 1
    return

def worker_two():
    count = 5
    while count > 0:
        #print "Worker two"
        time.sleep(5)
        count -= 1
    return


def join_thread(t):
    while t.is_alive():
        t.join(timeout=1)

threads = []
t1 = threading.Thread(target = worker_one)
t2 = threading.Thread(target = worker_two)
t1.start()
t2.start()

#t1.join()
#t2.join()
#print t1.is_alive()
#join_thread(t1)
#join_thread(t2)
print "Program finish"
