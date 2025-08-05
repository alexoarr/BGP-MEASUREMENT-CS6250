# BGP-MEASUREMENT-CS6250
#!/usr/bin/env python3

import pybgpstream

"""
CS 6250 BGP Measurements Project

Notes:
- Edit this file according to the project description and the docstrings provided for each function
- Do not change the existing function names or arguments
- You may add additional functions but they must be contained entirely in this file
"""

# Task 1A: Unique Advertised Prefixes Over Time
def unique_prefixes_by_snapshot(cache_files):
    """
    Retrieve the number of unique IP prefixes from each of the input BGP data files.
    """
    unique_prefixes = []
    for fpath in cache_files:
        stream = pybgpstream.BGPStream(data_interface="singlefile")
        stream.set_data_interface_option("singlefile", "rib-file", fpath)
        prefixes = set()
        for rec in stream.records():
            for elem in rec:
                p = elem.fields.get("prefix")
                if p:
                    prefixes.add(p)
        unique_prefixes.append(len(prefixes))
    return unique_prefixes

# Task 1B: Unique Autonomous Systems Over Time
def unique_ases_by_snapshot(cache_files):
    """
    Retrieve the number of unique ASes from each of the input BGP data files.
    """
    unique_ases = []
    for fpath in cache_files:
        stream = pybgpstream.BGPStream(data_interface="singlefile")
        stream.set_data_interface_option("singlefile", "rib-file", fpath)
        ases = set()
        for rec in stream.records():
            for elem in rec:
                path = elem.fields.get("as-path")
                if path:
                    for asn in path.split():
                        ases.add(asn)
        unique_ases.append(len(ases))
    return unique_ases

# Task 1C: Top-10 Origin AS by Prefix Growth
def top_10_ases_by_prefix_growth(cache_files):
    """
    Compute the top 10 origin ASes ordered by percentage increase of advertised prefixes.
    """
    snapshots = []
    for fpath in cache_files:
        stream = pybgpstream.BGPStream(data_interface="singlefile")
        stream.set_data_interface_option("singlefile", "rib-file", fpath)
        origin_map = {}
        for rec in stream.records():
            for elem in rec:
                p = elem.fields.get("prefix")
                path = elem.fields.get("as-path")
                if p and path:
                    tokens = path.split()
                    origin = tokens[-1]
                    origin_map.setdefault(origin, set()).add(p)
        snapshots.append(origin_map)

    growth = {}
    all_origins = set().union(*snapshots)
    for origin in all_origins:
        first = next(i for i, snap in enumerate(snapshots) if origin in snap)
        last = len(snapshots) - 1 - next(i for i, snap in enumerate(reversed(snapshots)) if origin in snap)
        a = len(snapshots[first].get(origin, []))
        b = len(snapshots[last].get(origin, []))
        if a > 0:
            growth[origin] = (b - a) / a

    top10 = sorted(growth, key=lambda x: growth[x], reverse=True)[:10]
    return sorted(top10, key=lambda x: growth[x])

# Task 2: Routing Table Growth: AS-Path Length Evolution Over Time
def shortest_path_by_origin_by_snapshot(cache_files):
    """
    Compute the shortest AS path length for every origin AS from input BGP data files.
    """
    snapshots = []
    for fpath in cache_files:
        stream = pybgpstream.BGPStream(data_interface="singlefile")
        stream.set_data_interface_option("singlefile", "rib-file", fpath)
        shortest = {}
        for rec in stream.records():
            for elem in rec:
                path = elem.fields.get("as-path")
                if path:
                    tokens = path.split()
                    origin = tokens[-1]
                    length = len(set(tokens))
                    if length > 1:
                        cur = shortest.get(origin)
                        if cur is None or length < cur:
                            shortest[origin] = length
        snapshots.append(shortest)

    all_origins = set().union(*snapshots)
    return {o: [snap.get(o, 0) for snap in snapshots] for o in all_origins}

# Task 3: Announcement-Withdrawal Event Durations
def aw_event_durations(cache_files):
    """
    Identify AW events and compute explicit durations.
    """
    aw_durs = {}
    last_adv = {}
    for fpath in cache_files:
        stream = pybgpstream.BGPStream(data_interface="singlefile")
        stream.set_data_interface_option("singlefile", "upd-file", fpath)
        for rec in stream.records():
            for elem in rec:
                peer = elem.peer_address
                p = elem.fields.get("prefix")
                t = rec.time
                key = (peer, p)
                if elem.type == 'A':
                    last_adv[key] = t
                elif elem.type == 'W' and key in last_adv:
                    d = t - last_adv[key]
                    if d > 0:
                        aw_durs.setdefault(peer, {}).setdefault(p, []).append(d)
                    del last_adv[key]
    return aw_durs

# Task 4: RTBH Event Durations
def rtbh_event_durations(cache_files):
    """
    Identify RTBH events and compute durations.
    """
    # helper to form unique key per peer/prefix
    def make_key(peer, prefix):
        return f"{peer}|{prefix}"

    # detect if an element is a blackholing announcement
    def is_blackholing_event(elem):
        comms = elem.fields.get("communities") or elem.fields.get("community") or []
        for c in comms:
            if c.split(":")[-1] == "666":
                return True
        return False

    rtbh_durations = {}
    announce_ts = {}
    for fpath in cache_files:
        stream = pybgpstream.BGPStream(data_interface="singlefile")
        stream.set_data_interface_option("singlefile", "upd-file", fpath)
        for rec in stream.records():
            for elem in rec:
                if elem.type not in ("A", "W"):  # only announcements and withdrawals
                    continue
                ts = rec.time
                peer = elem.peer_address
                pfx = elem.fields.get("prefix")
                key = make_key(peer, pfx)
                if elem.type == "A":
                    if is_blackholing_event(elem):
                        announce_ts[key] = ts
                    else:
                        announce_ts.pop(key, None)
                else:  # Withdrawal
                    if key in announce_ts:
                        duration = ts - announce_ts[key]
                        if duration != 0:
                            rtbh_durations.setdefault(peer, {}).setdefault(pfx, []).append(duration)
                        del announce_ts[key]
    return rtbh_durations
