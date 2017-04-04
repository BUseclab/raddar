import argparse
from multiprocessing import Process
import tailer
import re
import shutil
import json
import jsonpickle
import logging
import os
import sys
from ConfigParser import SafeConfigParser
from detect import RansomwareDetect
from download import MalwareDownloader
from alerts.twitter import RansomwareTweet

logger = logging.getLogger('raddar')

class Config:

    def __init__(self, filepath):
        config = SafeConfigParser()
        config.read(filepath)

        for section in config.sections():
            for name, raw_value in config.items(section):
                try:
                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)
                setattr(self, name, value)


class RansomwareResult(object):
    def __init__(self):
        self.family = None 
        #If we cant find the family then dump it in here to help us figure it
        #out
        self.av_labels = None

        self.active = False

        #Sha256 of binary
        self.hash = None
    
class Raddar:

    def __init__(self, cuckoo_home, storage_dir, alert=None):#, downloader):
        self.cuckoo_home = cuckoo_home
        self.storage_dir = storage_dir
        self.alert_handler = alert
        #self.downloader = downloader

    def run(self):
        self._start_downloader()
        self._start_analysis_monitor()

    def _start_downloader(self):
        dl_dest = os.path.abspath(os.path.join(self.storage_dir, "downloaded"))
        if not os.path.exists(dl_dest):
            os.makedirs(dl_dest)
        dl = MalwareDownloader()
        p = Process(target=dl.run, args=(dl_dest,self.cuckoo_submit))
        p.start()

    def cuckoo_submit(self, path):
        """
        When a malware sample has been downloaded this is the callback to
        submit to cuckoo

        Return ID of the submission
        """
        db = Database()
        submit_id = db.add_path(path)
        logger.debug("\tSubmitted to Cuckoo as task %d"%( submit_id))

    def _start_analysis_monitor(self):
        """
        Monitor completed jobs from Cuckoo to be analyzed
        """
        p = re.compile(ur'#(\d+): analysis procedure completed')
        #Read logs to determine when a task is done
        cuckoo_log = os.path.abspath(os.path.join(self.cuckoo_home, "log/cuckoo.log")) 
        try:
            for line in tailer.follow(open(cuckoo_log)):
                m = re.search(p, line)
                if m:
		    try:
			task = int(m.group(1))
			cuckoo_task_dir = os.path.abspath(os.path.join(self.cuckoo_home, "storage/analyses/" + str(task) + "/"))
			logger.info("Analyzing " + str(cuckoo_task_dir))
			result = self.analyze_cuckoo_sample(cuckoo_task_dir)
                        if result:
                            logger.info("Analysis complete")
                            if result.active:
                                    logger.info("Active ransomware found in task " + str(cuckoo_task_dir))
                                    self.active_sample(cuckoo_task_dir, result)
                            else:
                                    logger.info("Malware not active")
    
		    except Exception as e:
			    logger.exception(e)
						

        except Exception as e:
            logger.exception(e)

    def analyze_cuckoo_sample(self, cuckoo_task_dir):
        """
        Args:
            cuckoo_task_dir The directory of a cuckoo result
        Return a RansomwareResult 
        """
        cuckoo_report_file = os.path.abspath(os.path.join(cuckoo_task_dir, "reports/report.json"))

        if not os.path.isfile(cuckoo_report_file):
	    logger.warn("Could not find file " + str(cuckoo_report_file) + " skipping")
            return None

        result = RansomwareResult()

        r = RansomwareDetect()
        r.parse_report(cuckoo_report_file)
        result.hash = r.get_hash()
        if not result.hash:
            logger.error("Sample does not have a hash in Cuckoo analysis")
            return None

        #First try and get a known family
        family = r.get_family()

        if family:
            result.family = family 
            logger.debug("Family {}".format(result.family))
        else:
            result.av_labels = str(r.av_label_histogram())
            logger.debug("Couldnt get family {}".format(result.av_labels))

        if r.is_active():
            result.active = True
            logger.info("Ransomware is active")

        return result

    def active_sample(self, cuckoo_task_dir, result):
        """ Handler when an active sample is found """
        active_dir = os.path.abspath(os.path.join(self.storage_dir, "active"))
        if not os.path.exists(active_dir):
            os.makedirs(active_dir)

        result_dir = os.path.abspath(os.path.join(active_dir, result.hash))
        logger.info("Moving {} to {}".format(cuckoo_task_dir, result_dir))
        shutil.move(cuckoo_task_dir, result_dir)

        ransomware_report = os.path.abspath(os.path.join(result_dir, "ransom.json"))
        
        #Write RADDAR result to directory
        self.dump_results(ransomware_report, result)

        # Send alert
        # TODO make alerts more customizable with some sort of template
	try:
            if self.alert_handler:
                self.alert_handler.alert(result.hash, result.family)
            else:
                logger.warn("Alert not sent because not set")
	except Exception as e:
	    logger.exception(e)


    def dump_results(self, file, result):
        with open(file, 'w') as outfile:
            json.dump(json.loads(jsonpickle.encode(result)), outfile, indent=4) 


def cuckoo_running():
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    for pid in pids:
	try:
	    p = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read()
            if "cuckoo.py" in p:
                return True
	except IOError: # proc has already terminated
	    continue
    return False

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Real-time Automation to Discover, Detect and Alert of Ransomware (RADDAR)")
    parser.add_argument("cuckoo", help="Cuckoo home directory")
    parser.add_argument("storage", help="Directory to place Cuckoo tasks that are ransomare and downloaded samples")
    parser.add_argument("--alert",  help="Send alert with this configuration file")
    args = parser.parse_args()
    
    if not cuckoo_running():
        print "Cuckoo must be running!"
        sys.exit()

    #Set up logging
    basicformat = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logging.basicConfig(level=logging.DEBUG,
                       format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename="raddar.log"
                        )
    ch = logging.StreamHandler()
    logging.getLogger('').addHandler(ch)


    #Add to path so we can use its API
    sys.path.append(args.cuckoo)
    from lib.cuckoo.core.database import Database

    raddar = None
    if args.alert:
        config = Config(args.alert)
        alert_handler = RansomwareTweet(config.consumer_key, config.consumer_secret, config.access_token, config.access_token_secret)
        raddar = Raddar(args.cuckoo, args.storage, alert=alert_handler)
    else:
        raddar = Raddar(args.cuckoo, args.storage)

    raddar.run()

