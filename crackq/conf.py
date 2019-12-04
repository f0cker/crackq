"""
Helper function for parsing config file
"""
import configparser
import logging

from logging.config import fileConfig

# Setup logging
fileConfig('log_config.ini')
logger = logging.getLogger()
conf_file = '/var/crackq/files/crackq.conf'


def hc_conf():
        """
        Parse config file and return dictionary of file
        locations
        for rules, wordlists, logs etc
        :return: dictionary containing conf entries
        """
        logger.info("Reading from config file {}".format(conf_file))
        config = configparser.ConfigParser()
        config.optionxform = str
        config.read(conf_file)
        conf_dict = {s: dict(config.items(s)) for s in config.sections()}
        #logger.debug("Conf Dictionary:\n{}".format(conf_dict))
        return conf_dict
