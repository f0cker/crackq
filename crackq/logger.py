"""Setup logging handler"""
#!/usr/bin/env python
import logging
from logging.config import fileConfig

# Setup logging
fileConfig('log_config.ini')
logger = logging.getLogger()
