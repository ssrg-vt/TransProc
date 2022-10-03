#!/usr/bin/python3

import threading
import time
import subprocess
import os

THREADS = 3 #max 3
RUN_DURATION = 60 #seconds
IDEAL_RUN_DURATION = 3600 #seconds
COUNTER = [0, 0, 0]
ACTUAL_RUN_DURATION = [0, 0, 0]

class CustomThread (threading.Thread):
    def __init__(self, threadID, jobSet):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.jobSet = jobSet
      self.jobSetIdx = threadID

    def run(self):
        counter = 0
        start = time.perf_counter()
        while True:
            self._runJobSet()
            counter += 1
            diff = time.perf_counter() - start
            if diff > RUN_DURATION:
                ACTUAL_RUN_DURATION[self.threadID] = diff
                break
        COUNTER[self.threadID] = counter

    def _runJobSet(self):
        if self.jobSetIdx >= len(self.jobSet):
            self.jobSetIdx = 0
        subprocess.run(self.jobSet[self.jobSetIdx],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.STDOUT)
        self.jobSetIdx += 1

def main():
    threads = []
    jobSetBin = ["cg_x86-64", "ep_x86-64", "mg_x86-64"]
    jobSet = [os.path.join(os.path.dirname(__file__), b) for b in jobSetBin]
    for b in jobSet:
        assert os.path.isfile(b), f"File {b} does not exist"

    for i in range(THREADS):
        threads.append(CustomThread(i, jobSet))
        threads[-1].start()

    for t in threads:
        t.join()

    print("Jobs executed:" , COUNTER)
    print("Actual Run Duration:" , ACTUAL_RUN_DURATION)

    throughput = [(COUNTER[i]/ACTUAL_RUN_DURATION[i])*IDEAL_RUN_DURATION \
            for i in range(len(COUNTER))]

    print("Throughput (jobs/hr) per thread:", throughput)
    print("Net throughput (jobs/hr):", sum(throughput))
main()
