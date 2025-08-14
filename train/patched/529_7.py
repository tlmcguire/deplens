
"""
Testing the paths descriptor
"""


import os

from unittest import mock


TESTDATA = os.path.join(os.path.dirname(__file__), "testdata")
TESTCONF = os.path.join(TESTDATA, "testconf.yaml")


@mock.patch('confire.config.yaml')
def test_use_yaml_safe_load(mock_yaml):
    """
    Ensure we're using yaml.safe_load not yaml.load
    """
    from confire.config import Configuration
    Configuration.CONF_PATHS = [TESTCONF]
    Configuration.load()

    mock_yaml.safe_load.assert_called_once()
    mock_yaml.load.assert_not_called()
