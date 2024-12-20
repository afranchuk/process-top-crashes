#!/usr/bin/env python3

import json
import multiprocessing as mp
import subprocess as sp
import subprocess
import os
import sys
import requests

from datetime import datetime, timedelta, timezone

MAX_PROCESS = 16

def get_out_names(process, chan, actor=None):
    out = "{}_{}".format(process, chan)
    if actor and actor != "none":
        out += "_{}".format(actor)
    return out

def obj_to_cli(o, versions):
    for chan in o["channels"]:
        if chan not in versions.keys():
            raise ValueError

        out_file_names = get_out_names(o["process_name"], chan, o["ipc_actor"] if "ipc_actor" in o.keys() else None)
        crash_json_file = "crash-ids/{}".format(out_file_names)
        json_file = "processed/{}".format(out_file_names)

        base = "python3 crashes.py -i {} -d {} -u {} -q {}".format(crash_json_file, json_file, "https://sql.telemetry.mozilla.org", o["redash"])

        if "lower_client_limit" in o.keys():
            base += " -l {}".format(o["lower_client_limit"])

        if "ipc_actor" in o.keys():
            base += " -a {}".format(o["ipc_actor"])

        params = [
            "version={}".format(versions[chan]),
            "process_type={}".format(o["process_name"]),
            "channel={}".format(chan)
        ]

        rv = base + " " + " ".join(map(lambda x: "-p {}".format(x), params))
        yield rv

def fn_worker(q):
    while not q.empty():
        cmd = q.get()
        if cmd is None:
            break
        
        if len(sys.argv) > 1 and sys.argv[1] == "-s":
            print(cmd)
        else:
            sp.check_call(cmd.split(" "), shell=False)

def maybe_correct_version(now_date, chan, version_field, json_req):
    date_string = json_req[chan]
    if len(date_string) == 25:
        chan_date = datetime.fromisoformat(date_string)
    elif len(date_string) == 10:
        chan_date = datetime.strptime(date_string, "%Y-%m-%d").astimezone(timezone.utc)
    else:
        raise ValueError("Unexpected date string length: {}".format(len(date_string)))
    version = int(json_req[version_field].split('.')[0])
    diff = now_date - chan_date
    if diff < timedelta(days=2):
        version -= 1
        print("[{chan}] Detected {diff} time difference, fallback to {ver}".format(chan=chan, diff=diff, ver=version))
    return version

def get_versions():
    rv = {}
    now_date = datetime.now(timezone.utc)
    for (chan, chan_date) in [("nightly", "nightly_start"), ("beta", "beta_1")]:
        base_url = "https://whattrainisitnow.com/api/release/schedule/?version={}".format(chan)
        req = requests.get(base_url)
        if not req.ok:
            raise IndexError
        rv[chan] = maybe_correct_version(now_date, chan_date, "version", req.json())

    req = requests.get("https://product-details.mozilla.org/1.0/firefox_versions.json")
    if not req.ok:
        raise IndexError
    rv["release"] = maybe_correct_version(now_date, "LAST_RELEASE_DATE", "LATEST_FIREFOX_VERSION", req.json())

    return rv

def generate():
    all_cli = []

    versions = get_versions()
    
    os.makedirs("crash-ids", exist_ok=True)
    os.makedirs("processed", exist_ok=True)
    with open("processes.json") as p:
        config = json.load(p)
        for p in config:
            for cli in obj_to_cli(p, versions):
                all_cli.append(cli)

    queue = mp.Queue()
    workers = [mp.Process(target=fn_worker, args=(queue, )) for _ in range(MAX_PROCESS)]

    for cli in all_cli:
        queue.put(cli)

    for worker in workers:
        worker.start()

    for worker in workers:
        worker.join()

if __name__ == "__main__":
    if not os.getenv("REDASH_API_KEY"):
        print("Please set REDASH_API_KEY env")
        exit()
    generate()
