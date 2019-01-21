#!/usr/bin/env python

import logging

logger = logging.getLogger(__name__)

import argparse
import os.path
import requests
import shutil
import hashlib
from multiprocessing.dummy import Pool as ThreadPool


def validate_file(file_path, hash):
	"""
	Validates a file against an MD5 hash value

	:param file_path: path to the file for hash validation
	:type file_path:  string
	:param hash:      expected hash value of the file
	:type hash:       string -- MD5 hash value
	"""
	m = hashlib.md5()
	with open(file_path, 'rb') as f:
		while True:
			chunk = f.read(1000 * 1000)  # 1MB
			if not chunk:
				break
			m.update(chunk)
	return m.hexdigest() == hash


def download_with_resume(url, file_path=None, hash=None, timeout=10, block_size=1000 * 1000):
	"""
	Performs a HTTP(S) download that can be restarted if prematurely terminated.
	The HTTP server must support byte ranges.

	:param url: url of the file to be downloaded
	:param file_path: the path to the file to write to disk
	:type file_path: string
	:param hash: hash value for file validation
	:type hash: string (MD5 hash value)
	:param timeout: time to give up on response in seconds
	:param block_size: size of the blocks to download
	"""
	# don't download if the file exists
	if os.path.exists(file_path):
		# still validate file
		if hash and not validate_file(file_path, hash):
			raise Exception('Error validating the file against its MD5 hash')
		logger.info('File passes MD5 validation')
		return

	tmp_file_path = file_path + '.part'

	first_byte = os.path.getsize(tmp_file_path) if os.path.exists(tmp_file_path) else 0
	if first_byte != 0:
		logging.debug('Resuming download at %.1fMB' % (first_byte / 1e6))

	file_mode = 'ab' if first_byte else 'wb'
	file_size = -1
	try:
		file_size = int(requests.head(url).headers['Content-Length'])
		logging.debug('File size is %s' % file_size)
		headers = {"Range": "bytes=%s-" % first_byte}
		r = requests.get(url, headers=headers, stream=True, timeout=timeout)
		with open(tmp_file_path, file_mode) as f:
			for chunk in r.iter_content(chunk_size=block_size):
				if chunk:  # filter out keep-alive new chunks
					f.write(chunk)
	except IOError as e:
		logging.debug('IO Error - %s' % e)
	finally:
		# rename the temp download file to the correct name if fully downloaded
		if file_size == os.path.getsize(tmp_file_path):
			# if there's a hash value, validate the file
			if hash and not validate_file(tmp_file_path, hash):
				raise Exception('Error validating the file against its MD5 hash')
			logger.info('File passes MD5 validation')

			shutil.move(tmp_file_path, file_path)
			logger.info("URL '%s' downloaded to '%s' ok", url, file_path)
			return True
		elif file_size == -1:
			raise Exception('Error getting Content-Length from server: %s' % url)
		return False


def download_all(urls, file_paths, hashes=None, timeout=10, block_size=1000 * 1000):
	length = len(urls)
	if hashes is None:
		hashes = (None for _ in range(length))
	with ThreadPool() as pool:
		return all(pool.starmap(download_with_resume, zip(urls, file_paths, hashes, (timeout for _ in range(length)),
		                                                  (block_size for _ in range(length)))))


def console_logging(level=logging.DEBUG, format="%(message)s"):
	for h in list(logger.handlers):
		logger.removeHandler(h)
	stream = logging.StreamHandler(sys.stdout)
	stream.setFormatter(logging.Formatter(format))
	logger.addHandler(stream)
	logger.setLevel(level)


def main(arg_list=None):
	if arg_list is None:
		arg_list = []
	parser = argparse.ArgumentParser(description='Restarting Downloader')

	parser.add_argument('URL',
	                    metavar='<url>',
	                    help='URL to load')
	parser.add_argument('OUTFILE',
	                    metavar='<filename>',
	                    help='Filename to write')

	parser.add_argument('-t', '--timeout', required=False, help='timeout', metavar='<seconds>', type=int, default='10')
	parser.add_argument('-c', '--chunk_size', required=False, help='Chunk size', metavar='<bytes>', type=int,
	                    default=1024 * 1024)
	parser.add_argument('-m', '--md5', required=False, help='MD5 hash to check', metavar='<md5>')
	parser.add_argument('-v', required=False, help='verbose output', action='store_true')

	args = parser.parse_args(arg_list)

	if args.v:
		logger.setLevel(logging.DEBUG)

	download_with_resume(args.URL, args.OUTFILE, hash=args.md5, timeout=args.timeout, block_size=args.chunksize)


if __name__ == "__main__":
	import sys

	console_logging(level=logging.INFO)
	main(sys.argv[1:])
