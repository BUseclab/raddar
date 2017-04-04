#  Real-time Automation to Discover, Detect and Alert of Ransomware (RADDAR)

RADDAR is a continuous malware analysis system to find active ransomware. This
project is a modified open source version of the one used in the
[paper](http://cs-people.bu.edu/wfkoch/my-data/pubs/paybreak.pdf), 
```
Kolodenker, Eugene, William Koch, Gianluca Stringhini, and Manuel Egele.
"PayBreak: Defense against cryptographic ransomware." In Proceedings of the 2017
ACM Asia Conference on Computer and Communications Security (ASIACCS). ACM
(Association for Computing Machinery), 2017.
```
 

```
usage: raddar.py [-h] [--alert ALERT] cuckoo storage


positional arguments:
  cuckoo         Cuckoo home directory
  storage        Directory to place Cuckoo tasks that are ransomare and
                 downloaded samples

optional arguments:
  -h, --help     show this help message and exit
  --alert ALERT  Send alert with this configuration file

```

# Installation
* Install [Cuckoo](http://docs.cuckoosandbox.org/en/latest/installation/)
* Add Cuckoo home directory to `PYTHONPATH`, `export
  PYTHONPATH=/cuckoo/location/`
* Install dependencies `pip install -r requirements.txt`

# Details 

## Discover
RADDAR will actively look for new malware samples and download them to be
analyzed by Cuckoo. Upon the first time RADDAR is started  directory  named `downloaded` will be created in the `storage` directory to
store all of the malware downloaded.

Currently malware is automatically downloaded from vxvault and malc0de.


## Detect
If a downloaded binary has been labelled as ransomware, the Cuckoo analysis and
RADDAR analysis, `ransom.json`, are placed in `<storage>/active/`. 

RADDAR will attempt to identify the ransomware AV label. Newer versions of
Cuckoo normalize AV labels, however RADDAR will attempt to do this on its own if
not available. The label is then matched against a compiled list of ransomware
families stored in `ransomware_families.txt`. 


### Alert
At the moment Tweets are only supported for alerts. See `twitter.cfg` for
parameters required.



## Road Map
* The end goal of RADDAR is to have an automated continuous system to detect
  active malware samples. Detection modules will allow different types of
malware to be identified. 
* Integrate new findings into VirusTotal and other databases.
* Improve modularity and create a plugin architecture. 
