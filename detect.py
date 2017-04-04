import dpkt
import json
import sys
import os
import magic
import logging
import re
import argparse
import cStringIO
import gzip
import shutil
import zlib
import math
import traceback
import socket
import operator
import codecs
import time
import datetime

__author__ = 'Wil Koch'
__version__ = '0.0.1'
__contact__ = "wfkoch@bu.edu"


logger = logging.getLogger('detection')

class RansomwareIntel:
	"""
	File name of the Cuckoo report
	"""
	REPORT_FILENAME = "report.json"

	"""
	Default number of files needed to be encrypted for this binary to be considered ransomware
	"""
	MODIFY_THRESHOLD = 10

	def __init__(self, binary_storage = None):
            self.binary_storage = binary_storage
            self.known_families = self.import_families()

	def parse_report(self, report):
            self.report = json.load(open(report, 'rb'))

	def get_hash(self):
            """ Get SHA256 hash of binary """
            if "target" in self.report:
                if "file" in self.report["target"]:
                    if "sha256" in self.report["target"]["file"]:
                        return self.report["target"]["file"]["sha256"]
            return None

        def is_active(self):
            # TODO Removed libmagic test, needs to be improved. 
            # Need to look into what it would take to mount the snapshop and 
            # manually inspect VM. 
            isActive = False
            read_then_deleted = self.read_then_moved_or_deleted_or_overwritten() 
            logger.info("Number files read then deleted/moved {}".format(len(read_then_deleted)))
            if len(read_then_deleted) >= RansomwareIntel.MODIFY_THRESHOLD:
                return True
            return False

	def get_files_by_op(self, op):
            files = []
            try:
                summary = self.report['behavior']['summary']
                files = summary['file_%s'%op]
            except Exception as e:
                pass
            return files 

	def read_then_moved_or_deleted_or_overwritten(self):
             
            files = []
            moved = self.files_moved()
            #combind all moved

            all_moved = []
            for f in moved:
                all_moved += f
            deleted = self.get_files_by_op('deleted')
            written = self.get_files_by_op('written')
            
            for read in self.get_files_by_op('read'):
                if read in all_moved or read in deleted or read in written:
                    files.append(read)

            return files

        def av_label_histogram(self):
            """
            Return list of possible AV labels in order of popularity
            """
            detected = []
            p = re.compile('[^a-z]*')
            if "virustotal" in self.report:
                virustotal = self.report['virustotal']
                if virustotal:
                    if "scans" in virustotal:
                        scans = virustotal["scans"]
                        for key, value in scans.iteritems():
                            if value["detected"]:
                                has_normalized = False
                                if "normalized" in value: #Backwards compat
                                    if len(value["normalized"]) > 0:
                                        has_normalized = True
                                        detected+=map(lambda x: x.lower(), value["normalized"])

                                #Try to normalize our selves
                                if not has_normalized:
                                    family = value["result"]
                                    f = family.lower()
                                    #Split on anything not a letter
                                    detected += filter(None, p.split(f))
            hist = {}
            for f in  detected:
                if f in hist:
                    hist[f] +=1
                else:
                    hist[f] = 1

            sorted_freq = sorted(hist.items(), key=operator.itemgetter(1))
            #Have most popular first
            sorted_freq.reverse()

            #Only return labels that have 3 letters or more
            av_labels =[]
            for x in sorted_freq:
                label = x[0]
                if len(label) > 2:
                    av_labels.append(label)

            return av_labels

        def get_family(self):
            """ Get most popular ransomware AV label """
            av_labels = self.av_label_histogram()
            for label in av_labels:
                if label in self.known_families:
                    return label
            return None

        def import_families(self, families_file="ransomware_families.txt"):
            if not os.path.isfile(families_file):
                logger.warn("Cannot import families, file {} does not exist".format(families_file))

            with open(families_file, "r") as f:
                families = []
                for line in f:
                    if not line[0] == "#":
                        families.append(line.strip())

            return families




