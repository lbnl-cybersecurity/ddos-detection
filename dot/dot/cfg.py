# Configuration Files
# Reference:
#   https://github.com/osrg/ryu/blob/master/ryu/cfg.py

import oslo_config.cfg

CONF = oslo_config.cfg.ConfigOpts()

# re-export for convenience
from oslo_config.cfg import ConfigOpts

from oslo_config.cfg import BoolOpt
from oslo_config.cfg import IntOpt
from oslo_config.cfg import ListOpt
from oslo_config.cfg import MultiStrOpt
from oslo_config.cfg import StrOpt
from oslo_config.cfg import FloatOpt

from oslo_config.cfg import RequiredOptError
from oslo_config.cfg import ConfigFilesNotFoundError


