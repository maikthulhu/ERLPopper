# ERLPopper

This Python module and the example scripts should help you get started in evaluating/pentesting Erlang Runtime System (ERTS) nodes (enumerated by EPMD) using the Erlang Distribution Protocol. This is not an official or to-spec implementation, and it is not very fast. It does not interact with Erlang Port Mapper Daemon (EPMD) at all.

## Example Usage
```bash
# Check if a cookie is valid for a given node
./erl_cookie_checker.py localhost:12345 MYSECRETCOOKIE

# Check if a list of cookies is valid for a given node
./erl_cookie_checker.py localhost:12345 /path/to/cookie_list

# Check if a list of cookies is valid for a given list of nodes
./erl_cookie_checker.py /path/to/target_list /path/to/cookie_list

# Validate a cookie and run the id command if successful
./erl_check_cookie_run_cmd.py localhost:12345 MYSECRETCOOKIE id

# Validate a list of cookies and run the id command if successful, given a list of hosts
./erl_check_cookie_run_cmd.py /path/to/target_list /path/to/cookie_list id

# Brute force a node given a target and seed interval (more info below)
./erl_brute_by_seed_interval.py localhost:12345 0,8675309
```

## Explanation
[Erlang](https://en.wikipedia.org/wiki/Erlang_(programming_language)) is a [functional programming language](https://en.wikipedia.org/wiki/Functional_programming) and runtime (Erlang/OTP). Erlang Port Mapper Daemon (EPMD) is a service responsible for tracking and enumerating (and advertising) Erlang service cluster nodes. Nodes communicate using the Erlang Distribution Protocol. The `ERLPopper.py` module can attempt to communicate with cluster nodes (_NOT EPMD_). Clusters require a common cookie among the nodes. All someone needs to participate in the cluster (and get RCE) is a leaked/discovered cookie.

The example scripts act as a client to the given node(s) and use the given cookie(s) to either validate that a cookie is good (`erl_cookie_checker.py`), validate a cookie and run a given OS command (`erl_check_cookie_run_cmd.py`), or attempt to brute force a cookie given a range of seed values (`erl_brute_by_seed_interval.py`).

At node startup, a cookie value can be user-supplied (_highly recommended_). Otherwise Erlang/OTP will generate one at startup if not supplied. The built-in cookie generator is limited to a string of 20 uppercase characters (`[A-Z]{20}`) which is a somewhat limited keyspace.

**IMPORTANT**: The brute-force-by-seed script will only work for targets using one of these auto-generated cookies (and with enough time).

### Maths
I'm not a professional mathmetician. The [gteissier/erl-matter](https://github.com/gteissier/erl-matter) repo has some great programs/scripts aimed at using maths to analyze a list of cookies and derive an interval of seeds, or to fill in partially leaked cookies. I haven't tried to recreate any of those.

I borrowed the cookie generator function from the above repo and implemented it here (as a static method in `ERLPopper.py`). This cookie generator will spit out a string of 20 uppercase characters if you provide an (`unsigned long long`) integer between 0 and 68719476735 (36 bits). This limit was also borrowed from the above repo so see that for a better explanation.

Given the above range (or "interval"), that is 68.7 billion different possible seeds. Each seed can generate a string that is 20 bytes long. A complete list of possible cookies (in a text file with newlines) in that range would be 1.44 TB (`(68.7 * 10^9) * 21`).

For comparison, the entire `[A-Z]{20}` key space (`26^20`) would be `1.99 * 10^28`. If you want a name for that number, I think it's 19.9 octillion (or 19.9 thousand quadrillion). It's kind of large. An entire list of possible cookies would be that number * 21 (20 chars + 1 newline), resulting in 19.9 billion _exabytes_. Ain't nobody got time for that.

## Previous Works
This project leaned _heavily_ on the work that came before, as well as the ERTS documentation. These resources are listed below and I urge you to check them out for more background.
- [gteissier/erl-matter](https://github.com/gteissier/erl-matter) (github.com, Guillaume Teissier)
- [4369 - Pentesting Erlang Port Mapper Daemon (epmd)](https://book.hacktricks.xyz/pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd) (book.hacktricks.xyz, Carlos Polop)
- [Erlang distribution RCE and a cookie bruteforcer](https://insinuator.net/2017/10/erlang-distribution-rce-and-a-cookie-bruteforcer/) (insinuator.net, Daniel Mende)
- [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework/pull/11089) (github.com, Milton Valencia (wetw0rk))
- [Erlang Distribution Protocol docs](https://erlang.org/doc/apps/erts/erl_dist_protocol.html#protocol-between-connected-nodes) (erlang.org)

## Motivation
The primary motivation for writing this module was to help me understand the existing tools and figure out why they all seemed to be failing. Knowing what I know now, I probably would not have gone through the trouble, but it was a good exercise and a lot of fun and I'm mostly happy with the result. My hope is to help others by casting this and the documentation into the ~~void~~ open source community.

A secondary motivation was to create an implementation of this as a module for [axiom](https://github.com/pry0cc/axiom/) so the load of brute forcing a given seed interval could be distributed among many systems.

## Troubleshooting
I have not tested this on a wide range of systems (yet - 31 Aug 2021) and the "new" protocol (ERTS >= 5.7.2) has not been implemented, as it wasn't necessary for my purposes. Without some more testing and development, this may not work for you.

With that said, the root cause of the original problem I encountered was the clients advertising capability flags that the server didn't like. If you suspect (or have confirmed) that this is your issue, use the `erl` command line tool for your OS/distribution, start a packet capture, and connect to a node you control. Wireshark will show you the flags value that was passed, and you can use that in the module instead of the set I found. See [TODO] for detailed information and steps.