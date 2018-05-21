thread_queues = [] # List of thread queues
class ClientThread(threading.Thread):
    def __init__(self):
        myqueue = Queue.Queue() #Client queue
        clientqueues.append(myqueue)
        ...
def MessageAllClients(message):
    global clientqueues
    for queue in clientqueues:
        queue.put(message)