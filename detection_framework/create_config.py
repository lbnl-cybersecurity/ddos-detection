# Creates a new formatted config file using configobj
# Can create the config file using this method, or just writing to it directly

from configobj import ConfigObj
config = ConfigObj()
config.filename = "config.ini"
#
# Add detection tests here
# config['tests']['test_name'] = "module_name.class_name"
#
config['tests'] = {}
config['tests']['test1'] = "entropy_test.Entropy"
config['tests']['test2'] = "dns_test.RequestResponse"
#
# Test thresholds
#
config['Entropy_thresh'] = "0.3"
config['DNS_thresh'] = "10000000"
#
config.write() 
