## LBNL DDoS Detection on Science Networks
This software is a modular detection tool indended to support for monitoring network logs in order to detect denial of service attacks on "research and education" networks that disambiguates such attacks from sustained, high-volume network flows characteristic of large science projects, and referred to as "elephant flows."

This tool currently monitors a directory for nfcapd files.  Given an nfcapd directory, this tool will continuously check for newly added log files and apply each analytics module in a separate thread.  For example, one thread can calculate the entropy scores for each observed flow, while another thread monitors the number of DNS responses.  

Usage: detection_main.py -i netflow_directory -o log_name

Main module: detection_main.py

The individual detection tests are defined as classes within python modules.  The config.ini file determines which tests will be loaded. 
To add a new test, do the following:
1.  Define the detection test as a class.
2.  In the class, create a function called run_test which takes an nfdump file as input.  The start_test() function in detection_tests.py calls this.
3.  Then you can add it to the config.ini file by adding "test_name = module_name.class_name"
4.  The tester class also needs a variable called "log_entry".  When tester.log_entry is not empty, the entry is recorded to the log by the function feeding nfdump files to the tester. 
5.  Variables such as test thresholds can be modified using config.ini

config.ini contains variables for setting test parameters and which tests to run.  The variables are loaded into the global dictionary test_vars. 

For questions, please contact Sean Peisert <sppeisert@lbl.gov>
