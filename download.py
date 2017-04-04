"""
Modified from malware downloader obtain from Amin Kharraz
"""
from bs4 import BeautifulSoup as bs
import sys
import re
import hashlib
import socket
import datetime
import time
import os
import magic
import urllib2
from urllib2 import URLError, HTTPError
import argparse
import logging


now = datetime.datetime.now()
str(now)
timeout = 15
socket.setdefaulttimeout(timeout)

logger = logging.getLogger("downloader")


class PageParser(object):
    def parse(self, page):
        pass

class Malc0deParser(PageParser):

    def parse(self, page):
	mal = []
	for row in page('description'):
		mal.append(row)
	del mal[0]
	mlc_sites = []
	for row in mal:
		site = re.sub('&amp;', '&', str(row).split()[1]).replace(',', '')
		mlc_sites.append(site)
	return mlc_sites

class VXValutParser(PageParser):
    def parse(self, page):
        urls = []
	logger.debug("Extracting from VXVault")
	vxv = []
	count = 0
	for row in page('pre'):
                vxv = row.string.split('\r\n')
	vxv[:4]
	vxv[-1]
	for row in vxv:
                urls.append(row)
        	#process_row(row)
        #Skip the first 3 becaues its a header 
        return urls[4:]


class RaddarDownloader(object):
    def __init__(self):
        pass

    def cuckoo_submit(self, path):
        """
        Return ID of the submission
        """
        db = Database()
        return db.add_path(path)

class MalwareDownloader(RaddarDownloader):
    def __init__(self):
        pass

    def run(self, dest, callback=None):
        counter = 0
        timeout = 60*60
        # TODO Need to make this more generic, and modular. Have ability to 
        # add the repositories and parser in config file
        while True:
            submit_counter = 0
            counter += 1
            logger.info("Fetch counter %d"%counter)
            vxvault_page = self.get_page('http://vxvault.siri-urz.net/URL_List.php')
            vxvault_count = 0
            vxvault_submit = 0
            if vxvault_page:
                parser = VXValutParser()
                urls = parser.parse(vxvault_page)
                vxvault_count = len(urls)
                logger.debug("Attempting to download {} binaries from vxvault".format(len(urls)))
                vxvault_submit += self.download_binaries(urls, output_dir=dest,
                                                         callback=callback)
                logger.debug("Submitted {} of {} VXVault to Cuckoo".format(vxvault_submit,
                         vxvault_count))

            malc0de_page = self.get_page('http://malc0de.com/rss')
            malc0de_count = 0
            malc0de_submit = 0
            if malc0de_page:
                parser = Malc0deParser()
                urls = parser.parse(malc0de_page)
                malc0de_count = len(urls)
                logger.debug("Attempting to download {} binaries from malc0de".format(len(urls)))
                malc0de_submit += self.download_binaries(urls, output_dir=dest,
                                                         callback=callback)
                logger.debug("Submitted {} of {} Malc0de to Cuckoo".format(malc0de_submit,
                         malc0de_count))

            logger.debug("Submitted {} of {} to Cuckoo".format((vxvault_submit+malc0de_submit),
                         (vxvault_count+malc0de_count)))
            logger.debug("Going to sleep")	
            time.sleep(timeout)
            
# TODO are these still active? Need a VT one
#		malwarebl(parse('http://www.malwareblacklist.com/mbl.xml'))
#		minotaur(parse('http://minotauranalysis.com/malwarelist-urls.aspx'))
#		malc0de(parse('http://malc0de.com/rss'))	

    def get_page(self, url):
            req = urllib2.Request(url)
            req.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)')
            try: 
                    http = bs(urllib2.urlopen(req), "lxml")
                    return http
            except Exception as e: 
                    logger.error("Failed to get page from {}".format(url))
                    return None


    def download_binaries(self, urls, output_dir=".", callback=None):
        dl_counter = 0
        for url in urls:
            logger.debug("{}".format(url))
            #Some simply do not have a url
            if not url:
                continue

            if not 'http' in url:
                    url = 'http://' + url

            
            #url_hash = hashlib.sha256(url).hexdigest()
            binary_dir_name = urllib2.quote(url, safe='')
            #Use url hash for dir so we dont donwload every time
            binary_dir = os.path.abspath(os.path.join(output_dir,
                                                      binary_dir_name))
            #logger.debug("Binary location %s"%binary_dir)
            #If weve already downloaded it skip
            if os.path.exists(binary_dir): # and len(os.listdir(binary_dir)) > 0:
                logger.debug("\tSkipping, already downloaded")
                continue

            #Not there so download
            try:
                logger.debug("\tDownloading")
                #The location where binary is saved is the hash of the url
                if not os.path.exists(binary_dir):
                    os.makedirs(binary_dir)

                bin = urllib2.urlopen(url).read()
                file_type = magic.from_buffer(bin)
                logger.debug("\tType {}".format(file_type))
                if not ("PE32" in file_type):
                    continue

                bin_hash = hashlib.sha256(bin).hexdigest()
                fpath = os.path.join(binary_dir, str(bin_hash))

                #if not os.path.exists(fpath):
                with open(fpath, 'wb') as f:
                    f.write(bin)
                logger.debug("\tSaved file with sha256: %s" % ( bin_hash))
                if callback:
                    callback(fpath)
                    dl_counter +=1

            except HTTPError as e:
                logger.error("\tError: Code %d"%(e.code))	
            except URLError as e:
                logger.error("\tError: %s"%(e.reason))
            except Exception as e:
                logger.error("\tError downloading {}".format(e))

        return dl_counter

if __name__ == "__main__":
    basicformat = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logging.basicConfig(level=logging.DEBUG,
                       format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
    filename="malwaredl.log"
                        )
    ch = logging.StreamHandler()
    logging.getLogger('').addHandler(ch)

    parser = argparse.ArgumentParser(description='Download and submit malware to cuckoo')
    parser.add_argument("output", help="Download location of malware")
    args = parser.parse_args()
    logger.info("Malware Downloader v2.0")
    logger.info("Running Crawler at %s"% now)

    dl = Downloader()
    dl.run(args.output)

	
        
	
