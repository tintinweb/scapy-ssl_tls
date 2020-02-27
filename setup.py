#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import with_statement
import os
import platform
import re
import shutil
import sys
from setuptools import setup
from setuptools.command.install import install as _install
import site as _site
import pkg_resources

def get_site_packages():
    """
    This is a hack to work around site.getsitepackages() not working in
    virtualenv. See https://github.com/pypa/virtualenv/issues/355
    """
    # Another hack...
    # Relies on the fact that os.py is in the dir above site_packages
    os_location = os.path.dirname(os.__file__)
    site_packages = []
    # Consider Debain/Ubuntu custom
    for site in ["site-packages", "dist-packages"]:
        site_path = os.path.join(os_location, site)
        if os.path.isdir(site_path):
            site_packages.append(site_path)
    try:
        site_packages += _site.getsitepackages()
    except AttributeError as ex:
        print("WARNING: Error trying to call site.getsitepackages(). Exception: %r" % ex)
        print("         Do you have sufficient permissions?") 
        print("         Otherwise this could probably be virtualenv issue#355")
    return list(set(site_packages))


def get_scapy_locations(sites):
    scapy_locations = []
    for site in sites:
        try:
            dirs = os.listdir(site)
        except OSError as oe:
            print("Non exisiting site-package reported: %s. Skipping" %
                  site, file=sys.stderr)
        else:
            # Look for scapy folder in site-packages
            for dir_ in dirs:
                if dir_.startswith("scapy") and not dir_.endswith("egg-info"):
                    scapy_path = os.path.join(site, dir_)
                    if os.path.isdir(scapy_path):
                        # Look for layers folder under the scapy install folder
                        # (can be nested)
                        for root, dirs, files in os.walk(scapy_path):
                            for dir_ in dirs:
                                if dir_ == "layers":
                                    scapy_locations.append(root)
    print("INFO: Installing scapy-ssl_tls layers to: %s" % repr(scapy_locations))
    return scapy_locations


def get_layer_files_dst(sites, path="scapy_ssl_tls"):
    data_files = []
    scapy_locations = get_scapy_locations(sites)
    layer_files = []
    for layer_file in os.listdir(path):
        # Copy only python files, and exclude module file from copy to scapy
        if layer_file != "__init__.py" and layer_file.endswith(".py"):
            layer_file_path = os.path.join(path, layer_file)
            if os.path.isfile(layer_file_path):
                layer_files.append(layer_file_path)
    for scapy_location in scapy_locations:
        data_files.append(
            (os.path.join(scapy_location, "layers"), layer_files))
    return data_files


class install(_install):

    def run(self):
        _install.run(self)
        self.execute(
            _post_install, (self.install_lib,), msg="running post install task")


def _post_install(dir_):
    """ Patches scapy config.py to add autoloading of the ssl_tls layer
    Takes a backup in the form of a config.py.bak file
    """

    def patch_ll(ll_match):
        match_start = ll_match.start()
        prefix = ll_match.start(1) - match_start
        suffix = ll_match.end(1) - match_start
        orig_code = ll_match.group(0)
        return orig_code[:prefix] + ', "ssl_tls",' + orig_code[suffix:]
    ll_regex = re.compile(r"load_layers = \[[^\]]*(,)[^,\]]*\]", re.DOTALL)

    scapy_locations = get_scapy_locations(get_site_packages())
    for scapy_location in scapy_locations:
        scapy_config = os.path.join(scapy_location, "config.py")
        if os.path.isfile(scapy_config):
            shutil.copy(scapy_config, scapy_config + ".bak")
            with open(scapy_config, "r+") as f:
                config_source = f.read()
                f.truncate(0)
                f.seek(0)
                f.write(ll_regex.sub(patch_ll, config_source))


def os_install_requires():
    # load dependencies from requirements.txt
    dependencies = [l.strip() for l in read("requirements.txt").strip().split('\n') if l.strip()]
    #dependencies = ["scapy>=2.2.0,<2.3.3", "pycrypto", "tinyec"]
    # Scapy on OSX requires dnet and pcapy, but fails to declare them as dependencies
    #  - with pip 9.x we're switching from unmaintained dnet to pydumbnet
    #  - in order to avoid API errors we're switching from pcapy to pypcap
    if platform.system() == "Darwin":
        dependencies.extend(("pydumbnet", "pypcap"))
    return dependencies


def read(fname):
    fd = open(os.path.join(os.path.dirname(__file__), fname))
    data = fd.read()
    fd.close()
    return data

#### setup main ####
# warn user about the unmaintained state of pycrypto
try:
    pkg_resources.require("pycrypto")
    print ("WARNING: Found PyCrypto to be installed in your environment.")
    print ("         Please note that the PyCrypto project seems to be in an unmaintaned state with known security issues. Consider switching to other alternatives. Ref: https://github.com/tintinweb/scapy-ssl_tls/pull/82#issuecomment-260004605")
except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
    pass

setup(
    name="scapy-ssl_tls",
    version="2.0.0",
    packages=["scapy_ssl_tls"],
    author="tintinweb",
    author_email="tintinweb@oststrom.com",
    description=(
        "An SSL/TLS layer for scapy the interactive packet manipulation tool"),
    license="GPLv2",
    keywords=["scapy", "ssl", "tls", "layer", "network", "dissect", "packets", "decrypt"],
    url="https://github.com/tintinweb/scapy-ssl_tls/",
    download_url="https://github.com/tintinweb/scapy-ssl_tls/tarball/v2.0.0",
    # generate rst from .md:  pandoc --from=markdown --to=rst README.md -o README.rst (fix diff section and footer)
    long_description=read("README.rst") if os.path.isfile("README.rst") else read("README.md"),
    install_requires=os_install_requires(),
    test_suite="nose.collector",
    tests_require=["nose"] + os_install_requires(),
    # Change once virtualenv bug is fixed
    # data_files = get_layer_files_dst(sites=site.getsitepackages())
    data_files=get_layer_files_dst(get_site_packages()),
    cmdclass={"install": install}
)
