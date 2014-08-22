### IPSentry Files to Zabbix  ###
# Code Written by Cade McCormick  
# Produced as an Internship project under Matrix Group International #
# This script was released with the Mozilla Public Liscense Version 2.0 #

# This code will access an IPSentry backup zip file and parse through the
# "Machine" tag of the XML files for information that can be used to reconfigure
# the server monitoring in Zabbix 2.2.5.
# The script will then insert the aquired data 
# into the Zabbix mysql database using a series of cursor executions. 
# The servers that are configured to be monitored are either added to "Web Checks"
# (servers with web scenarios) and "IP Address Pings" (those without checks). 

# The backup file is expected to be in the IPZ format

# Imported modules

import MySQLdb  # Allows for cursor executes. 
import HTMLParser # Uses handler methods to make sense of HTML elements 
import urllib # Makes sense of unusual urls
from bs4 import BeautifulSoup  # Puts the AddInArgs into a standard HTML format
import xml.etree.ElementTree as ET # Parses through the XML files
import zipfile  # Allows for processing of zip files
import sys  # Allows file referrals in the command line when running the script

DBHOST = "localhost"
DBUSER = "zabbix"
DBPASS = "zabbix"
INTERVAL = 300 #The Web scenario update interval in seconds

## Example "Machine" tag from an XML File ##
"""
<Machine MUID="{20010213-163940-0005674243-59980.88000}" 
  MachName="Sample_MachName"	### If IType = 4, the IPAddress is set to the MachName (because the IType 4 files do not indicate ip addresses.) 
  Description="http://www.sample.com"
  Notes="Notes:09-23-2008 @ 13:00:58Converted from V4 to V5 Computer"
  Deleted="0"
  GroupName=""
  IType="3"		### IType = 3 indicates this file is used for creating a web check. 
  TimeOut="30"
  TTL="255"
  UseICMPDll="0"
  ReturnResultData="0"
  PacketSize="64"
  RetryCount="4"
  AutoRetryCount="1"
  AutoRetry="0" Suspended="0"
  SuspendedUntil=" 0"
  Reversed="0" StatOutput="0"
  StatOutputPage=""
  StatOutputTitle="Stat Report"
  StatOutputURL=""
  StatOutputTemplateMUID="{00000000-000000-0000000000-00000.00000}"
  LogGraphData="0" LogGraphDataTemplateMUID="{00000000-000000-0000000000-00000.00000}"
  SyncFailureCount="0"
  DataToRecv=""
  DataToSend=""
  Dependent="{20110916-161205-1188565492-58326.14936}" 	### Dependent is used to determine the original host of this web check.
  IPAddress="" 					     	### IPAddress is used to create hosts for web checks to be assigned to. 
  IPPort=""
  DriveMap=" "
  AlertOrder="APELXDS"
  DriveShareName=""
  UserName=""
  Password="=O="
  MinFreeSpace="0"
  NTMachine=""
  NTServiceName="<SVCITEMS><SVC  Name="" Desc=""/></SVCITEMS>"
  NTServiceDesc=""
  NTUserName=""
  NTPassword="=O="
  TriggerWeight="1"
  BackReferenceList=""
  AddInTitle="HTTP/s Enhanced Web Monitor"
  AddInLoadName="IPSHttpPost.IPSHttpPostCtlV5"
  AddInArgs="					### AddInArgs contains important information for the web checks, including the url of the site, and the required string to check for.
    <HTTPCFGV5	 				### The method for how the required string in extracted depends on the tyoe of HTTP tag. If CFG, "urllib.unquote_plus" is used to restore the string to a usable format. If CFGV5, "html_parse.unescape" is used to restore the string.
    URL="http://www.sample.org" 			### The url provides zabbix with the site address to connect to. 
    EXP="&lt;h2&gt;Latest blog post&lt;/h2&gt;"	### The exp provides zabbix with a modified string that can be interpreted into a readable format. 
    METHOD="GET"
    COMP="CONTENT"				### Unfortunately, zabbix cannot use a Required String method to prevent monitoring of a page that includes that string in the source. Therefore, if the comp = NOMATCH, this web check is simply skipped (there are other types of checks for these sites). 

  # The remainder is unused
    USER=""
    PWD="=O="
    PROXYSERVER=""
    PROXYPORT=""
    BYPASS=""
    PROXYUSER=""
    PROXYPASS="=O="
    TIMEOUT="15"
    USERAGENT="Mozilla/4.0 (compatible; Mozilla/4.0; IPSentry HTTP Posting Add-In)"
    AUTHNTLM="1"
    REDIR="0"
    HTTP11="0"
    RETCONTENT="0"
    COOKIES="0"
    SSLDynamic="0"
    SSLCertOnly="0"
    SSLEval="0"
    SSLEffectiveDate="0"
    SSLIssuer="0"
    SSLSerial="0"
    SSLSubject="0"
    SSLUsage="0"
    SSLVersion="0"
    SSLExpiring="0"
    SSLExpireDays="30"
    SSLExpired="0"
    SSLAuthError="0"/>"
  PollFrequency="1"
  FailingPollFrequency="1"
  CusKey0=""
  CusKey1=""
  CusKey2=""
  CusKey3=""
  CusKey4=""
  CusKey5=""
  CusKey6=""
  CusKey7=""
  CusKey8=""
  CusKey9=""
  DriveScale="0">
"""
# This function parses through all the XML files in a zip backup. If the IType in a 
# file equals three, the parent of the XML file is checked for an IP Address. 
# If the IPAddress is not already a registered host, a host is added to 
# "Web Checks" as well as all the web scenarios for the XML IType = 3 file. 

def webCheckCreate(zip_file, db):
    # Parses through the XML file
    tree = ET.parse(zip_file)
    root = tree.getroot()


    my_cursor = db.cursor() # Sets the database cursor


# If IType has a value, that value is stored.
    if len(root.attrib.get("IType")):
        value = root.attrib.get("IType").encode('utf-8')
   
    # If the value is three, the following data will be stored to be used for
    # the database inserts.
	if value == "3":
	    url = ""
	    req_string = ""
    # The AddInArgs are stored in a usable format.
	    add_in_args = root.attrib.get("AddInArgs")
	    arg_soup = BeautifulSoup(add_in_args)
	    arg_soup_str = str(arg_soup)

	    # If "httpcfg" is the beginning of the args tag...
	    if "httpcfg" in arg_soup_str and "httpcfgv5" not in arg_soup_str:
		# Identifies the tag from the html	
		arg_tag = arg_soup.httpcfg 
		# Stores the value of the url attribute
		broken_url = arg_tag['url']
		# Url is repaired
		url = urllib.unquote(broken_url) 
		# Stores the value of the exp attribute
		broken_req_string = arg_tag['exp']
		# Required string is repaired
		req_string = urllib.unquote_plus(broken_req_string) 
		# Stores the value to the comp attribute
		comp = arg_tag['comp'] 

	    # If "httpcfgv5" is the beginning of the args tag
	    elif "httpcfgv5" in arg_soup_str:
		# Identifies the tag from the html	
		arg_tag = arg_soup.httpcfgv5 
		# Stores the value of the url attribute    	
		broken_url = arg_tag['url']
		# Url is repaired 
		url = urllib.unquote(broken_url) 
		# Stores HTMLParser class
		html_parse = HTMLParser.HTMLParser() 
		# Stores the value of the exp attribute
		broken_req_string = arg_tag['exp']
		# Required string is repaired     
		req_string = html_parse.unescape(broken_req_string)
		# Stores the value to the comp attribute
		comp = arg_tag['comp'] 

	    # If the comp is NOMATCH, then the function ends 
	    # (these files will not be used for configuring web checks)
	    if comp == "NOMATCH":
		my_cursor.close()
		return

	    # This sets an ip address value in advance for all the 
	    # IType 4 files that will not store any hostname
	    ip_address = "IType 4s"

	    # The parsed parent is of the IType = 3 file is stored 
	    # from the "Dependent" attribute
	    parent = root.attrib.get("Dependent")
	    unzipped_parent = unzipped_file.open(parent + ".XML")
	    itype = ET.parse(unzipped_parent).getroot().attrib.get("IType")
	    unzipped_parent.close()

	    # If the file's parent isn't the default...
	    if parent != "{00000000-000000-0000000000-00000.00000}" \
		 or parent != "":
		# Parent's filename is created
		parent_part_xml = parent + ".XML"
		# Parent is opened
		parent_xml = unzipped_file.open(parent_part_xml)    
		# Parent's parse is stored
		parent_attrib = ET.parse(parent_xml).getroot().attrib 
		# Parent is closed
		parent_xml.close()                
		
		# If the parent has an IType of four, 
                # the ip_address becomes the MachName
		if parent_attrib.get("IType") == "4":         
		    ip_address = parent_attrib.get("MachName") 

		# While the parent has an IType of three and its parent is not 
		# the default, reset the value of "parent" 
		# to the parent of the current parent
		while parent_attrib.get("IType") == "3":        
		    parent2 = parent_attrib.get("Dependent")   
		    # If the parent is the default, the ip_address equals 
		    # the url and the while is broken
		    if parent2 == "{00000000-000000-0000000000-00000.00000}": 
			ip_address = url
			break
		    parent2_part_xml = parent2 + ".XML"
		    parent_xml = unzipped_file.open(parent2_part_xml)
		    # The parent_attrib is reset
		    parent_attrib = ET.parse(parent_xml).getroot().attrib 
		    parent_xml.close()

		# If the parent has an IType of zero,
		# the ip_address equals the ip address
		if parent_attrib.get("IType") == "0":
		    ip_address = parent_attrib.get("IPAddress")

	    # If the file's parent is the default and its IType equals three,
	    # ip_address is set to the url
	    elif parent == "{00000000-000000-0000000000-00000.00000}" \
                    and itype == 3:
		ip_address = url
	    
	    # If the parent is a default and the itype isn't three,
	    # raise an error
	    else:
		raise Exception("OBVIOUSLY BAD" )

	    # Non-latin characters can be managed
	    db.set_character_set('utf8')
	    my_cursor.execute('SET NAMES utf8;') 
	    my_cursor.execute('SET CHARACTER SET utf8;')
	    my_cursor.execute('SET character_set_connection=utf8;')


	    # A tuple of the host tuple with the same name if it exists
	    my_cursor.execute(" SELECT name FROM hosts"
			      " WHERE name = %s; ", (ip_address)) 
	    host_names = my_cursor.fetchall()

	    
	    if (ip_address,) not in host_names:

		# Prints the host being added
		print "New Host " + ip_address 


		# A new hostid is created 
		my_cursor.execute(" SELECT MAX(hostid) FROM hosts; ")
		old_hostid_max = my_cursor.fetchone()[0]
		if old_hostid_max == None:
		    old_hostid_max = 0
		new_hostid_max = old_hostid_max + 1 

		# A new host is created and the ids table is updated accordingly
		my_cursor.execute("INSERT INTO hosts ( hostid,  host,  status,"
				  " ipmi_authtype, name, flags) VALUES"
				  " ( %s, %s, 0, -1, %s, 0); " , 
				  ( new_hostid_max, ip_address, ip_address ))
		my_cursor.execute(" UPDATE ids SET nextid = '%s'"
				  " WHERE table_name = 'hosts'; " , 
				  (new_hostid_max + 1))

		print ip_address, url		
 
		# Group names are stored as indidual tuples under a larger tuple
		my_cursor.execute(" SELECT name FROM groups; ")
		group_names = my_cursor.fetchall()

		# If this group already exists, a hostgroupid for the host is
		# added to hosts_groups
		if ('Web Check Group',) in group_names:
		    my_cursor.execute(" SELECT MAX(hostgroupid) FROM"
				      " hosts_groups; ")
		    old_hostgroupid_max = my_cursor.fetchone()[0]
		    if old_hostgroupid_max == None:
			old_hostgroupid_max = 0
		    new_hostgroupid_max = old_hostgroupid_max + 1
		    my_cursor.execute(" INSERT INTO hosts_groups (hostgroupid,"
				      " hostid, groupid) VALUES ( %s, %s, 8); ",				      ( new_hostgroupid_max, new_hostid_max ))
		    my_cursor.execute(" UPDATE ids SET nextid = '%s' WHERE"
				      " table_name = 'hosts_groups'; " ,
				      (new_hostgroupid_max + 1))
		# If this group doesn't exist, it is created and the 
		# hostgroupid info is added to hosts_groups
		else:
		    my_cursor.execute(" INSERT INTO groups ( groupid, name )"
				      " VALUES ( 8, 'Web Check Group' ); ")
		    my_cursor.execute(" SELECT MAX(hostgroupid)"
				      " FROM hosts_groups; ")
		    old_hostgroupid_max = my_cursor.fetchone()[0]
		    if old_hostgroupid_max == None:
			old_hostgroupid_max = 0
		    new_hostgroupid_max = old_hostgroupid_max + 1
		    my_cursor.execute(" INSERT INTO hosts_groups (hostgroupid,"
				      " hostid, groupid) VALUES ( %s, %s, 8); ",				      ( new_hostgroupid_max, new_hostid_max ))
		    my_cursor.execute(" UPDATE ids SET nextid = '%s'"
				      " WHERE table_name = 'hosts_groups'; " ,
				      (new_hostgroupid_max + 1))

	    # The httptestid is set
	    my_cursor.execute(" SELECT MAX(httptestid) FROM httptest; ")
	    old_httptestid_max = my_cursor.fetchone()[0]
	    if old_httptestid_max == None:
		old_httptestid_max = 0
	    new_httptestid_max = old_httptestid_max + 1

	    # The httptestitemids are set
	    my_cursor.execute(" SELECT MAX(httptestitemid) FROM httptestitem; ")
	    old_httptestitemid_max = my_cursor.fetchone()[0]
	    if old_httptestitemid_max == None:
		old_httptestitemid_max = 0
	    new_httptestitemid_1 = old_httptestitemid_max + 1
	    new_httptestitemid_2 = new_httptestitemid_1 + 1
	    new_httptestitemid_3 = new_httptestitemid_2 + 1


	    # The httpstepid is set
	    my_cursor.execute(" SELECT MAX(httpstepid) FROM httpstep; ")
	    old_httpstepid_max = my_cursor.fetchone()[0]
	    if old_httpstepid_max == None:
		old_httpstepid_max = 0
	    new_httpstepid_max = old_httpstepid_max + 1

	    # The httpstepitemids are set
	    my_cursor.execute(" SELECT MAX(httpstepitemid) FROM httpstepitem; ")
	    old_httpstepitemid_max = my_cursor.fetchone()[0]
	    if old_httpstepitemid_max == None:
		old_httpstepitemid_max = 0
	    new_httpstepitemid_1 = old_httpstepitemid_max + 1
	    new_httpstepitemid_2 = new_httpstepitemid_1 + 1
	    new_httpstepitemid_3 = new_httpstepitemid_2 + 1


	    # The itemappids are set
	    my_cursor.execute("SELECT MAX(itemappid) FROM items_applications; ")
	    old_itemappid_max = my_cursor.fetchone()[0]
	    if old_itemappid_max == None:
		old_itemappid_max = 0
	    new_itemappid_1 = old_itemappid_max + 1
	    new_itemappid_2 = new_itemappid_1 + 1
	    new_itemappid_3 = new_itemappid_2 + 1
	    new_itemappid_4 = new_itemappid_3 + 1
	    new_itemappid_5 = new_itemappid_4 + 1
	    new_itemappid_6 = new_itemappid_5 + 1

	    # The itemids are set
	    my_cursor.execute(" SELECT MAX(itemid) FROM items; ")
	    old_itemid_max = my_cursor.fetchone()[0]
	    if old_itemid_max == None:
		old_itemid_max = 0
	    new_itemid_1 = old_itemid_max + 1
	    new_itemid_2 = new_itemid_1 + 1
	    new_itemid_3 = new_itemid_2 + 1
	    new_itemid_4 = new_itemid_3 + 1
	    new_itemid_5 = new_itemid_4 + 1
	    new_itemid_6 = new_itemid_5 + 1
	    # Stores the value of the current host for assigning web checks
	    my_cursor.execute(" SELECT hostid FROM hosts"
			      " WHERE name = %s; " , 
			      (ip_address))
	    current_hostid = my_cursor.fetchone()[0]

	    # Print check
	    print current_hostid, url, root.attrib.get("MachName"), 
	    print ip_address, req_string 

	    # The applicationid is set and an application is created		
	    my_cursor.execute(" SELECT applicationid from applications"
			      " WHERE hostid = %s AND name = %s" ,
			       (current_hostid, 'Web Checks'))
	    row = my_cursor.fetchone()
	    if row == None:
		my_cursor.execute(" SELECT MAX(applicationid) + 1"
				  " FROM applications; ")
		new_applicationid_max = my_cursor.fetchone()[0]
		my_cursor.execute(" INSERT INTO applications (applicationid,"
				  " hostid, name) VALUES ( %s, %s,"
				  " 'Web Checks' ) ; " ,
				  (new_applicationid_max, current_hostid ))
		my_cursor.execute(" UPDATE ids SET nextid = '%s'"
				  " WHERE table_name = 'applications'; " ,
				  (new_applicationid_max + 1))
	    else:
		new_applicationid_max = row[0]

	    # The "key_"s are set using the url
	    test_in_sc = "web.test.in[" + url + ",,bps]"
	    test_fail = "web.test.fail[" + url + "]"
	    test_error = "web.test.error[" + url + "]"
	    test_in_st = "web.test.in[" + url + "," + url + ",bps]"
	    test_time = "web.test.time[" + url + "," + url + ",resp]"
	    test_rspcode = "web.test.rspcode[" + url + "," + url + "]"


	    # Items are inserted and ids are updated
	    print test_in_sc, test_in_st
	    try:	
	        my_cursor.execute(""" INSERT INTO items (itemid, type, hostid,"""
			          """ name, key_, delay, history, trends, units,"""
			          """ params, description) VALUES ( %s, 9, %s,"""
			          """ 'Download speed for scenario "$1".', %s,"""
			          """ 300, 30, 90, 'Bps', '', '' ), ( %s, 9, %s,"""
			          """ 'Failed step of scenario "$1".', %s, 300,"""
			          """ 30, 90, '', '', '' ), ( %s, 9, %s,"""
			          """ 'Last error message of scenario "$1".', %s,"""
			          """ 300, 30, 90, '', '', '' ), ( %s, 9, %s,"""
			          """ 'Download speed for step "$2" of scenario"""
			          """ "$1".', %s, 300, 30, 90, 'Bps', '', '' ),"""
			          """ ( %s, 9, %s, 'Response time for step "$2" """
			          """ of scenario "$1".', %s, 300, 30, 90, 's',"""
			          """ '', '' ), ( %s, 9, %s, 'Response code for"""
			          """ step "$2" of scenario "$1".', %s, 300, 30,"""
			          """ 90, '', '', '' )  ; """ ,
			           (new_itemid_1, current_hostid, test_in_sc,
			           new_itemid_2, current_hostid, test_fail,
                                   new_itemid_3, current_hostid, test_error,
                                   new_itemid_4, current_hostid, test_in_st,
                                   new_itemid_5, current_hostid, test_time,
                                   new_itemid_6, current_hostid, test_rspcode ))
		my_cursor.execute(" UPDATE ids SET nextid = '%s'"
			              " WHERE table_name = 'items'; " ,
			              (new_itemid_6 + 1))
	    except MySQLdb.IntegrityError:
		print "It looks like you are trying to insert something into a table that already has that data."
		print "You are currently trying to add host %s to the zabbix database on %s." % (ip_address, DBHOST,)
		print "Please confirm that you are connecting to the correct database."
		sys.exit(-1)
	    # Items_applications are inserted and ids are updated	
	    my_cursor.execute(" INSERT INTO items_applications (itemappid,"
			      " applicationid, itemid) VALUES ( %s, %s, %s ),"
			      " (%s, %s, %s ), ( %s, %s, %s ), ( %s, %s, %s ),"
			      " ( %s, %s, %s ), ( %s, %s, %s ) ; " ,
			      (new_itemappid_1, new_applicationid_max,
			       new_itemid_1, new_itemappid_2,
			       new_applicationid_max, new_itemid_2,
			       new_itemappid_3, new_applicationid_max,
			       new_itemid_3, new_itemappid_4,
			       new_applicationid_max, new_itemid_4,
			       new_itemappid_5, new_applicationid_max,
			       new_itemid_5, new_itemappid_6,
			       new_applicationid_max, new_itemid_6 ))
	    my_cursor.execute(" UPDATE ids SET nextid = '%s'"
			      " WHERE table_name = 'items_applications'; " ,
			      (new_itemappid_6 + 1))

	    # A web scenario is created and ids are updated	
	    my_cursor.execute(" INSERT INTO httptest (httptestid, name,"
			      " applicationid, delay, variables, agent, hostid)"
			      " VALUES ( %s, %s, %s, %s, '',"
			      " 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT"
			      " 6.1; Trident/6.0)', %s); " , 
			      (new_httptestid_max, url, new_applicationid_max,
			       INTERVAL, current_hostid ))
	    my_cursor.execute(" UPDATE ids SET nextid = '%s'"
			      " WHERE table_name = 'httptest'; " ,
			      (new_httptestid_max + 1))

	    # Httptestitems are inserted and ids are updated	
	    my_cursor.execute(" INSERT INTO httptestitem (httptestitemid,"
			      " httptestid, itemid, type) VALUES ( %s, %s, %s,"
			      " 2 ),( %s, %s, %s, 3 ),( %s, %s, %s, 4 ); " ,
			      (new_httptestitemid_1, new_httptestid_max, 
			       new_itemid_1, new_httptestitemid_2, 
			       new_httptestid_max, new_itemid_2, 
                               new_httptestitemid_3, new_httptestid_max,
                               new_itemid_3 ))
	    my_cursor.execute(" UPDATE ids SET nextid = '%s'"
			      " WHERE table_name = 'httptestitem'; " ,
			       (new_httptestitemid_3 + 1))

	    # A step is inserted and ids are updated	
	    my_cursor.execute(" INSERT INTO httpstep (httpstepid, httptestid,"
			      " name, no, url, timeout, posts, required,"
			      " status_codes, variables) VALUES ( %s, %s, %s,"
			      " 1, %s, 15, '', %s, '200', ''); " , 
			      (new_httpstepid_max, new_httptestid_max, url,
			       url, req_string ))
	    my_cursor.execute(" UPDATE ids SET nextid = '%s'"
			      " WHERE table_name = 'httpstep'; " ,
			      (new_httpstepid_max + 1))

	    # Httpstepitems are inserted and ids are updated	
	    my_cursor.execute(" INSERT INTO httpstepitem (httpstepitemid,"
                              " httpstepid, itemid, type) VALUES ( %s, %s, "
                              "%s, 2 ),( %s, %s, %s, 1 ),( %s, %s, %s, 0 ); ",
                              (new_httpstepitemid_1,
                               new_httpstepid_max,
                               new_itemid_4,
                               new_httpstepitemid_2,
                               new_httpstepid_max,
                               new_itemid_5,
                               new_httpstepitemid_3,
                               new_httpstepid_max,
                               new_itemid_6 ))
	    my_cursor.execute(" UPDATE ids SET nextid = '%s'"
			      " WHERE table_name = 'httpstepitem'; " ,
			      (new_httpstepitemid_3 + 1))

	    # Cursor is closed
	    my_cursor.close ()


# This function parses through all the XML files in an IPZ backup. If the IType in a
# file equals zero, and the IPAddress is not already a registered host, a host
# is added to "IP Address Pings". 

def ipPingCreate(zip_file, db):
    # Parses through the XML file
    tree2 = ET.parse(zip_file)
    root2 = tree2.getroot()
    
    my_cursor = db.cursor() # Sets the database cursor
    
    # If IType has a value, that value is stored
    if len(root2.attrib.get("IType")):
        value = root2.attrib.get("IType").encode('utf-8') 
          
        # If the value is zero, and the IP Address isn't already a host... 
	if value == "0":
	    my_cursor.execute("SELECT name FROM hosts;")
	    host_names = my_cursor.fetchall()
	    ip_address = root2.attrib.get("IPAddress")
	    if (ip_address,) not in host_names:

		# A new hostid is created
                my_cursor.execute(" SELECT MAX(hostid) FROM hosts; ")
                old_hostid_max = my_cursor.fetchone()[0]
		if old_hostid_max == None:
	 	    old_hostid_max = 0
                new_hostid_max = old_hostid_max + 1

		# The host is added and the ids table is updated accordingly
                my_cursor.execute(" INSERT INTO hosts ( hostid,  host,  status,"
				  " ipmi_authtype, name, flags) VALUES ( %s,"
				  " %s, '0', '-1', %s, '0'); " , 
				  ( new_hostid_max, ip_address, ip_address ))
		my_cursor.execute(" UPDATE ids SET nextid = '%s' WHERE"
				  " table_name = 'hosts'; " ,
				  (new_hostid_max + 1))

		# Group names are stored as indidual tuples under a larger tuple
                my_cursor.execute(" SELECT name FROM groups; ")
                group_names = my_cursor.fetchall()

		# If this group already exists, a hostgroupid for the host
		# is added to hosts_groups
                if ('IP Address Pings',) in group_names:
                    my_cursor.execute(" SELECT MAX(hostgroupid) FROM"
				      " hosts_groups; ")
                    old_hostgroupid_max = my_cursor.fetchone()[0]
		    if old_hostgroupid_max == None:
			old_hostgroupid_max = 0
                    new_hostgroupid_max = old_hostgroupid_max + 1
                    my_cursor.execute(" INSERT INTO hosts_groups (hostgroupid,"
				      " hostid, groupid) VALUES (%s, %s, '9');", 	
				      ( new_hostgroupid_max, new_hostid_max ))
		    my_cursor.execute(" UPDATE ids SET nextid = '%s' WHERE"
				      " table_name = 'hosts_groups'; " ,
				      (new_hostgroupid_max + 1))

		# If this group doesn't exist, it is created and 
		# the hostgroupid info is added to hosts_groups
                else:
                    my_cursor.execute(" INSERT INTO groups ( groupid, name )"
				      " VALUES ( '9', 'IP Address Pings' ); ")
                    my_cursor.execute(" SELECT MAX(hostgroupid) FROM"
				      " hosts_groups; ")
                    old_hostgroupid_max = my_cursor.fetchone()[0]
		    if old_hostgroupid_max == None:
			old_hostgroupid_max = 0
                    new_hostgroupid_max = old_hostgroupid_max + 1
                    my_cursor.execute(" INSERT INTO hosts_groups (hostgroupid,"
				      " hostid, groupid) VALUES (%s, %s, '9');",				     
				      ( new_hostgroupid_max, new_hostid_max ))
		    my_cursor.execute(" UPDATE ids SET nextid = '%s' WHERE"
				      " table_name = 'hosts_groups'; " ,
				      (new_hostgroupid_max + 1))

	    # The cursor is closed
            my_cursor.close()




# The second argument in the command line when running the script is the backup IPZ file
try:
    unzipped_file = zipfile.ZipFile(sys.argv[1])
except IndexError:
    print "Make sure that when run this script is run,",
    print "the second argument is the IPZ file that data is drawn from."
    sys.exit(-1)
# The script connects to the mysql zabbix database
db = MySQLdb.connect(host = DBHOST,
		     user = DBUSER,
                     passwd = DBPASS,
                     db = "zabbix")


# The webCheckCreate function acts on the appropriate XML files from the IPZ backup
for zip_info in unzipped_file.infolist():
	
    if zip_info.filename.endswith("Dyn.XML") or not zip_info.filename.startswith("{"):
        continue
    else:
        zip_file = unzipped_file.open(zip_info)
        webCheckCreate(zip_file, db)
	zip_file.close()



# The ipPingCreate function acts on the appropriate XML files from the IPZ backup
for zip_info in unzipped_file.infolist():
	
    if zip_info.filename.endswith("Dyn.XML") or not zip_info.filename.startswith("{"):
        continue
    else:
        zip_file = unzipped_file.open(zip_info)
        ipPingCreate(zip_file, db)
	zip_file.close()



# Cursor is set
my_cursor = db.cursor()

# The number of the hosts added for each group is printed
my_cursor.execute("SELECT COUNT(*) from hosts_groups WHERE groupid = 8")
web_check_hosts = my_cursor.fetchone()[0]

my_cursor.execute("SELECT COUNT(*) from hosts_groups WHERE groupid = 9;")
ip_address_hosts = my_cursor.fetchone()[0]

print "Number of hosts in Web Checks: " + str(web_check_hosts) 
print "Number of hosts in IP Address Pings: " + str(ip_address_hosts) 


# Cursor is closed, changes are commited, and database is closed
my_cursor.close()
db.commit()
db.close()



