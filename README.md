testing taskcluster integration

Python utility for pulling Mozilla redash crash ping telemetry down and generating top crash reports for Firefox utility processes.

Note, to get the html displaying right, you'll need to download fontawesome webfonts and store it in the root under 'fontawesome'.

Usage:

-u (url)      : redash rest endpoint url<br/>
-k (str)      : redash user api key<br/>
-q (query id) : redash api query id<br/>
-n (name)     : local json cache filename to use (excluding extension)<br/>
-d (name)     : local html output filename to use (excluding extension)<br/>
-c (count)    : number of reports to process, overrides the default of 5000<br/>
-p (k=v)      : k=v redash query parameters to pass to the query request.<br/>

required -p parameters: process_type, version, channel

example: python crashes.py -n nightly -d nightly -u https://sql.telemetry.mozilla.org -k (userapikey) -q 79354 -p process_type=gpu -p version=89 -p channel=nightly

