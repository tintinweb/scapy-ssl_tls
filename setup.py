#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import site
import sys
from setuptools import setup
from setuptools.command.install import install

def get_scapy_locations(sites=site.getsitepackages()):
  scapy_locations = []
  for site in sites:
    try:
      dirs = os.listdir(site)
    except OSError as oe:
      print("Non exisiting site-package reported. Skipping", file=sys.stderr)
    else:
      # Look for scapy folder in site-packages
      for dir_ in dirs:
        if dir_.startswith("scapy") and not dir_.endswith("egg-info"):
          scapy_path = os.path.join(site, dir_)
          if os.path.isdir(scapy_path):
            # Look for layers folder under the scapy install folder
            for dir_ in os.listdir(scapy_path):
              if dir_ == "layers":
                scapy_locations.append(scapy_path)
  return scapy_locations

def get_layer_files_dst(path="src/scapy/layers/"):
  data_files = []
  scapy_locations = get_scapy_locations()
  layer_files = []
  for layer_file in os.listdir(path):
    layer_file_path = os.path.join(path, layer_file)
    if os.path.isfile(layer_file_path):
      layer_files.append(layer_file_path)
  for scapy_location in scapy_locations:
    data_files.append((os.path.join(scapy_location, "layers"), layer_files))
  return data_files

def read(fname):
  return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
  name = "scapy-ssl_tls",
  version = "0.0.1",
  author = "tintinweb",
  author_email = "tintinweb@oststrom.com",
  description = ("An SSL/TLS layer for scapy the interactive packet manipulation program"),
  license = "GPLv2",
  keywords = "scapy ssl tls",
  url = "https://github.com/tintinweb/scapy-ssl_tls/",
  long_description=read('README.md'),
  install_requires = [ "scapy", "pycrypto" ],
  data_files = get_layer_files_dst(),
  cmdclass = { "install":install }
) 
