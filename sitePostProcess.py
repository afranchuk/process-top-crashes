#!/usr/bin/env python3

import base64
import glob
import json
import re
import sys
import time
import zlib

OS_VERSION_NAMES = {
  "Mac": {
    "19.": 'macOS 10.15 "Catalina"',
    "20.": 'macOS 11 "Big Sur"',
    "21.": 'macOS 12 "Monterey"',
    "22.": 'macOS 13 "Ventura"',
    "23.": 'macOS 14 "Sonoma"',
    "24.": 'macOS 15 "Sequoia"',
  },
  "Windows": {
    "5.1": 'Windows XP',
    "5.2": 'Windows XP',
    "6.0": 'Windows Vista',
    "6.1": 'Windows 7',
    "6.2": 'Windows 8',
    "6.3": 'Windows 8.1',
    "10.0@10": 'Windows 10',
    "10.0@14": 'Windows 10',
    "10.0@15": 'Windows 10',
    "10.0@16": 'Windows 10',
    "10.0@17": 'Windows 10',
    "10.0@18": 'Windows 10',
    "10.0@19": 'Windows 10',
    "10.0@22": 'Windows 11',
    "10.0@26": 'Windows 11',
  },
}


class MultiselectFilter:
  def __init__(self, field):
    self._data = {'type': 'multiselect', 'field': field, 'values': set()}

  def set_pretty(self, name):
    self._data['pretty'] = name
    return self

  # Fields reference the pretty name of the field (or field name if no pretty name is set).
  def requires(self, field, value):
    self._data.setdefault('requires', {}).setdefault(field, []).append(value)
    return self

  def add(self, value):
    self._data['values'].add(value)
    return self

  def add_unset(self):
    self._data['unset'] = True
    return self

  def eject(self):
    self._data['values'] = list(self._data['values'])
    return self._data

channels = MultiselectFilter('channel')
processes = MultiselectFilter('process')
ipcactors = MultiselectFilter('ipc_actor').requires('process', 'utility').set_pretty('utility ipc actor').add_unset()
versions = MultiselectFilter('version')
oses = MultiselectFilter('os')
osversions = {}
arches = MultiselectFilter('arch')


entries = []
details = []
for file in glob.glob("processed/*-reports.json"):
  matches = re.match(r'processed/([a-z]+)_([a-z]+)(_[a-z-]+)?-reports\.json', file)
  assert matches is not None
  process = matches.group(1)
  channel = matches.group(2)
  ipc_actor = matches.group(3)
  if ipc_actor is not None:
    ipc_actor = ipc_actor[1:]

  channels.add(channel)
  processes.add(process)
  if ipc_actor is not None:
    ipcactors.add(ipc_actor)


  data = json.load(open(file))
  for sighash, sigdata in data.items():
    for report in sigdata["reportList"]:
      os = report["operatingsystem"]
      versions.add(report["firefoxver"])
      oses.add(os)
      arches.add(report["arch"])

      if os not in osversions:
        osversions[os] = MultiselectFilter('osversion').set_pretty(f"{os} version").requires('os', os)
      osversions[os].add(report["osversion"])

      entry = {
          "channel": channel,
          "process": process,
          "version": report["firefoxver"],
          "os": os,
          "osversion": report["osversion"],
          "arch": report["arch"],
          "date": report["crashdate"],
          "signature": sigdata["signature"],
          "clientid": report["clientid"],
          "reason": report["crashreason"],
          "type": report["type"],
      }

      if ipc_actor is not None:
        entry["ipc_actor"] = ipc_actor

      entries.append(entry)

      details.append({
        "crashid": report["crashid"],
        "stack": report["stack"],
      })

def os_versions_filters(osversions):
  def choose_version_entry(names, v):
    for prefix, name in names.items():
      if v.startswith(prefix):
        return { "value": v, "label": f"{name} ({v})" }
    return v

  def convert_version_values(os, flt):
    flt = flt.eject()
    if os in OS_VERSION_NAMES:
      flt['values'] = [choose_version_entry(OS_VERSION_NAMES[os], v) for v in flt.pop('values')]
    return flt

  return [convert_version_values(os, flt) for os, flt in osversions.items()]

# Filters with requires _must_ be listed after the filters that they require, for UX clarity.
filters = [
    channels.eject(),
    processes.eject(),
    ipcactors.eject(),
    oses.eject()
  ] + os_versions_filters(osversions) + [
    arches.eject(),
    versions.eject(),
  ]

meta = {
    "processUnixTime": time.time()
}

json.dump({"pings": entries, "filters": filters, "meta": meta}, open('site/pings.json', 'w'))

# Compress details so that it's in a format easily returned by the netlify function (otherwise it can exceed the 1GB memory limit...).
def compress(v):
  return base64.b64encode(zlib.compress(json.dumps(v).encode('utf-8'), wbits = zlib.MAX_WBITS | 16)).decode('utf-8')

compressed_details = list(map(compress, details))
json.dump(compressed_details, open('netlify/functions/ping-details/data.json', 'w'))
