#!/usr/bin/env python3

import glob
import json
import re
import sys

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

  def eject(self):
    self._data['values'] = list(self._data['values'])
    return self._data


files = glob.glob("processed/*-reports.json")

entries = []
details = []

channels = MultiselectFilter('channel')
processes = MultiselectFilter('process')
versions = MultiselectFilter('version')
oses = MultiselectFilter('os')
osversions = {}
arches = MultiselectFilter('arch')

for file in files:
  matches = re.match(r'processed/([a-z]+)_([a-z]+)-reports\.json', file)
  assert matches is not None
  process = matches.group(1)
  channel = matches.group(2)

  channels.add(channel)
  processes.add(process)

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

      entries.append({
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
      })

      details.append({
        "crashid": report["crashid"],
        "stack": report["stack"],
      })

# Filters with requires _must_ be listed after the filters that they require, for UX clarity.
filters = [
    channels.eject(),
    processes.eject(),
    oses.eject()
  ] + list(map(lambda x: x.eject(), osversions.values())) + [
    arches.eject(),
    versions.eject(),
  ]

json.dump({"pings": entries, "filters": filters}, open('site/pings.json', 'w'))
json.dump(details, open('site/netlify/functions/ping-details/data.json', 'w'))
