[comment]: # "Auto-generated SOAR connector documentation"
# Lastline

Publisher: Splunk Community  
Connector Version: 3\.0\.0  
Product Vendor: Lastline  
Product Name: Lastline  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.5  

This app supports executing investigative actions to analyze executables and URLs on the online Lastline sandbox

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Lastline asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Base URL for lastline service
**verify\_server\_cert** |  optional  | boolean | Verify Server Certificate
**timeout** |  required  | numeric | Timeout \(seconds\)
**license\_key** |  required  | password | License Key
**api\_token** |  required  | password | API Token
**account\_username** |  optional  | string | Push Account
**report\_url** |  optional  | string | Report URL for lastline service

### Supported Actions  
[detonate file](#action-detonate-file) - Run the file in the Lastline sandbox and retrieve the analysis results  
[get report](#action-get-report) - Query for results of an already completed task in Lastline  
[detonate url](#action-detonate-url) - Load a URL in the Lastline sandbox and retrieve the analysis results  
[test connectivity](#action-test-connectivity) - This action connects to the server to verify the connection
[get artifact](#action-get-artifact) - Loads artifacts from Lastline and stores them in Vault

## action: 'detonate file'
Run the file in the Lastline sandbox and retrieve the analysis results

Type: **investigate**  
Read only: **True**

This action requires the input file to be present in the vault and therefore takes the vault id as the input parameter\. <br/> This action supports PE, PDF, doc, etc\. for analysis\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of file to detonate | string |  `vault id`  `pe file` 
**file\_name** |  optional  | Filename to use | string |  `file name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_name | string |  `file name` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `pe file` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_length | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_md5 | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_sha1 | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_type | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.end | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.error | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.filename | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.ip | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.parent\_url | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.relation\_type | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.relation\_type\_str | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.start | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.status | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.task\_uuid | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.url | string | 
action\_result\.data\.\*\.report\.analysis\.result\.analysis\_ended | string | 
action\_result\.data\.\*\.report\.analysis\.result\.detector | string | 
action\_result\.data\.\*\.report\.analysis\.subject\.md5 | string | 
action\_result\.data\.\*\.report\.analysis\.subject\.subject | string | 
action\_result\.data\.\*\.report\.analysis\.subject\.type | string | 
action\_result\.data\.\*\.report\.analysis\.text\_from\_documents\.\*\.doc\_md5 | string | 
action\_result\.data\.\*\.report\.analysis\.text\_from\_documents\.\*\.doc\_sha1 | string | 
action\_result\.data\.\*\.report\.analysis\.text\_from\_documents\.\*\.text | string | 
action\_result\.data\.\*\.report\.analysis\.urls\_from\_documents\.\*\.child\_url\_type | string | 
action\_result\.data\.\*\.report\.analysis\.urls\_from\_documents\.\*\.source\_url | string | 
action\_result\.data\.\*\.report\.analysis\.urls\_from\_documents\.\*\.task\_uuid | string | 
action\_result\.data\.\*\.report\.analysis\.urls\_from\_documents\.\*\.url | string | 
action\_result\.data\.\*\.report\.analysis\_engine\_version | numeric | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.analysis\_reason | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.analysis\_subject\_id | numeric | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.delete\_date | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.description | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.ext\_info\.create\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.ext\_info\.file\_info | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.ext\_info\.llfile | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.ext\_info\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.ext\_info\.mime | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.ext\_info\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.ext\_info\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.ext\_info\.size | numeric | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.file\.abs\_path | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.file\.ext\_info\.create\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.file\.ext\_info\.file\_info | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.file\.ext\_info\.llfile | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.file\.ext\_info\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.file\.ext\_info\.mime | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.file\.ext\_info\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.file\.ext\_info\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.file\.ext\_info\.size | numeric | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.file\.filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.metadata\_type | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.name | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.retention\_date | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.dns\_queries\.\*\.dns\_server | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.dns\_queries\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.dns\_queries\.\*\.response\_flags | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.dns\_queries\.\*\.results | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_queries\.\*\.filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_queries\.\*\.status | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.abs\_path | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.accesses\.\*\.disposition | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.accesses\.\*\.options | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.ext\_info\.create\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.ext\_info\.file\_info | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.ext\_info\.llfile | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.ext\_info\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.ext\_info\.mime | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.ext\_info\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.ext\_info\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.ext\_info\.size | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.file\_attributes | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.iostatus | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.static\_pe\_information\.author | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.static\_pe\_information\.compile\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.static\_pe\_information\.description | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.static\_pe\_information\.imphash | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.static\_pe\_information\.original\_filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_reads\.\*\.static\_pe\_information\.version | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_renames\.\*\.existing\_file | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_renames\.\*\.new\_file | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_searches | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.abs\_path | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.accesses\.\*\.disposition | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.accesses\.\*\.options | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.ext\_info\.create\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.ext\_info\.file\_info | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.ext\_info\.llfile | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.ext\_info\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.ext\_info\.mime | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.ext\_info\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.ext\_info\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.ext\_info\.size | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.file\_attributes | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.iostatus | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.static\_pe\_information\.author | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.static\_pe\_information\.compile\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.static\_pe\_information\.description | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.static\_pe\_information\.imphash | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.static\_pe\_information\.original\_filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.file\_writes\.\*\.static\_pe\_information\.version | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.frequent\_api\_calls\.\*\.count | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.frequent\_api\_calls\.\*\.name | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.frequent\_api\_calls\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.frequent\_api\_calls\.\*\.tid | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.loaded\_libraries\.\*\.end\_address | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.loaded\_libraries\.\*\.filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.loaded\_libraries\.\*\.start\_address | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.number\_of\_stages | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.access | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.characteristics | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.executed\_pages | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.id | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.md5\_phys | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.name | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.offset | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.physical\_size | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.rva | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.trusted | boolean | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_data\.virtual\_size | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_description | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_type | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.object\_uuid | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.stages\.\*\.virtual\_address | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.memory\_region\_stages\.\*\.virtual\_address | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.mutex\_creates\.\*\.mutex\_name | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.mutex\_opens\.\*\.mutex\_name | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.network\_connections\.\*\.dst\_ip | string |  `ip` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.network\_connections\.\*\.dst\_port | numeric |  `port` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.network\_connections\.\*\.protocol | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.network\_connections\.\*\.src\_ip | string |  `ip` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.network\_connections\.\*\.src\_port | numeric |  `port` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.network\_connections\.\*\.type | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.analysis\_reason | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.ext\_info\.create\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.ext\_info\.file\_info | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.ext\_info\.llfile | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.ext\_info\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.ext\_info\.mime | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.ext\_info\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.ext\_info\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.ext\_info\.size | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.id | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.kernel\_mode | boolean | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.parent\_id | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.analysis\_subject\_id | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.arguments | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.bitsize | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.abs\_path | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.accesses\.\*\.disposition | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.accesses\.\*\.options | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.ext\_info\.create\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.ext\_info\.file\_info | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.ext\_info\.llfile | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.ext\_info\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.ext\_info\.mime | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.ext\_info\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.ext\_info\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.ext\_info\.size | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.file\_attributes | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.iostatus | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.static\_pe\_information\.author | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.static\_pe\_information\.compile\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.static\_pe\_information\.description | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.static\_pe\_information\.imphash | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.static\_pe\_information\.original\_filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.executable\.static\_pe\_information\.version | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.overview\.process\.process\_id | string |  `pid` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.patched\_sleeps\.\*\.count | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.patched\_sleeps\.\*\.new\_value | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.patched\_sleeps\.\*\.old\_value | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.analysis\_subject\_id | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.arguments | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.bitsize | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.abs\_path | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.accesses\.\*\.disposition | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.accesses\.\*\.options | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.ext\_info\.create\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.ext\_info\.file\_info | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.ext\_info\.llfile | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.ext\_info\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.ext\_info\.mime | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.ext\_info\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.ext\_info\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.ext\_info\.size | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.file\_attributes | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.iostatus | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.static\_pe\_information\.author | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.static\_pe\_information\.compile\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.static\_pe\_information\.description | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.static\_pe\_information\.imphash | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.static\_pe\_information\.original\_filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.executable\.static\_pe\_information\.version | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\.process\_id | string |  `pid` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.analysis\_subject\_id | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.arguments | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.bitsize | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.abs\_path | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.accesses\.\*\.disposition | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.accesses\.\*\.options | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.ext\_info\.create\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.ext\_info\.file\_info | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.ext\_info\.llfile | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.ext\_info\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.ext\_info\.mime | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.ext\_info\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.ext\_info\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.ext\_info\.size | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.file\_attributes | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.iostatus | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.static\_pe\_information\.author | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.static\_pe\_information\.compile\_timestamp | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.static\_pe\_information\.description | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.static\_pe\_information\.imphash | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.static\_pe\_information\.original\_filename | string |  `pe file` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.executable\.static\_pe\_information\.version | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.operations | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.process\_interactions\.\*\.process\_id | string |  `pid` 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.raised\_exceptions\.\*\.addr | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.raised\_exceptions\.\*\.code | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.raised\_exceptions\.\*\.exception\_count | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.raised\_exceptions\.\*\.exception\_name | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.registry\_deletions\.\*\.key | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.registry\_deletions\.\*\.value | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.registry\_reads\.\*\.data | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.registry\_reads\.\*\.key | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.registry\_reads\.\*\.value | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.registry\_writes\.\*\.data | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.registry\_writes\.\*\.key | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.registry\_writes\.\*\.value | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.service\_starts\.\*\.service\_name | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.analysis\_reason | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.bitsize | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.loaded\_libraries\.\*\.object\_description | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.loaded\_libraries\.\*\.object\_type | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.loaded\_libraries\.\*\.virtual\_address | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.memory\_blocks\.\*\.object\_data\.access | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.memory\_blocks\.\*\.object\_data\.executed\_pages | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.memory\_blocks\.\*\.object\_data\.trusted | boolean | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.memory\_blocks\.\*\.object\_description | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.memory\_blocks\.\*\.object\_type | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.memory\_blocks\.\*\.object\_uuid | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.memory\_blocks\.\*\.virtual\_address | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.pe\_images\.\*\.object\_description | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.pe\_images\.\*\.object\_type | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.pe\_images\.\*\.object\_uuid | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.pe\_images\.\*\.virtual\_address | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.snapshot\_id | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.snapshot\_timestamp | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.thread\_eips\.\*\.eip | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.snapshots\.\*\.thread\_eips\.\*\.tid | numeric | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.strings\_lists\.\*\.name | string | 
action\_result\.data\.\*\.report\.analysis\_subjects\.\*\.strings\_lists\.\*\.strings | string | 
action\_result\.data\.\*\.report\.format\.build\_version | numeric | 
action\_result\.data\.\*\.report\.format\.major\_version | numeric | 
action\_result\.data\.\*\.report\.format\.minor\_version | numeric | 
action\_result\.data\.\*\.report\.format\.name | string | 
action\_result\.data\.\*\.report\.malicious\_activity\.\*\.description | string | 
action\_result\.data\.\*\.report\.malicious\_activity\.\*\.type | string | 
action\_result\.data\.\*\.report\.md5 | string | 
action\_result\.data\.\*\.report\.mime\_type | string | 
action\_result\.data\.\*\.report\.overview\.analysis\_end | string | 
action\_result\.data\.\*\.report\.overview\.analysis\_engine | string | 
action\_result\.data\.\*\.report\.overview\.analysis\_engine\_version | string | 
action\_result\.data\.\*\.report\.overview\.analysis\_start | string | 
action\_result\.data\.\*\.report\.overview\.analysis\_termination\_reason | string | 
action\_result\.data\.\*\.report\.prefilter\_scanners\.\*\.detector\_id | string | 
action\_result\.data\.\*\.report\.prefilter\_scanners\.\*\.score | numeric | 
action\_result\.data\.\*\.report\.prefilter\_scanners\.\*\.test | boolean | 
action\_result\.data\.\*\.report\.prefilter\_scanners\.\*\.version | numeric | 
action\_result\.data\.\*\.report\.prefilter\_score | numeric | 
action\_result\.data\.\*\.report\.remarks\.info | string | 
action\_result\.data\.\*\.report\.score | numeric | 
action\_result\.data\.\*\.report\.uuid | string | 
action\_result\.summary\.id | string |  `lastline task id` 
action\_result\.summary\.result\_url | string |  `url`  `domain` 
action\_result\.summary\.score | numeric | 
action\_result\.summary\.target | string |  `file name` 
action\_result\.summary\.type | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Query for results of an already completed task in Lastline

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Task ID to get the results of | string |  `lastline task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `lastline task id` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_length | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_type | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.end | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.parent\_url | string |  `url`  `domain` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.relation\_type | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.start | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.status | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.url | string |  `url`  `domain` 
action\_result\.data\.\*\.report\.analysis\.result\.analysis\_ended | string | 
action\_result\.data\.\*\.report\.analysis\.result\.detector | string | 
action\_result\.data\.\*\.report\.analysis\.statics\.\*\.code | string | 
action\_result\.data\.\*\.report\.analysis\.statics\.\*\.media\_type | string | 
action\_result\.data\.\*\.report\.analysis\.strings\.\*\.str\_len | numeric | 
action\_result\.data\.\*\.report\.analysis\.strings\.\*\.str\_type | string | 
action\_result\.data\.\*\.report\.analysis\.strings\.\*\.value | string | 
action\_result\.data\.\*\.report\.analysis\.subject\.type | string | 
action\_result\.data\.\*\.report\.analysis\.subject\.url | string |  `url`  `domain` 
action\_result\.data\.\*\.report\.analysis\_engine\_version | numeric | 
action\_result\.data\.\*\.report\.analysis\_error | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.metadata\_type | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.name | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.retention\_date | string | 
action\_result\.data\.\*\.report\.extracted\_files\.\*\.file\_name | string | 
action\_result\.data\.\*\.report\.extracted\_files\.\*\.md5 | string | 
action\_result\.data\.\*\.report\.extracted\_files\.\*\.mime\_type | string | 
action\_result\.data\.\*\.report\.extracted\_files\.\*\.sha1 | string | 
action\_result\.data\.\*\.report\.extracted\_files\.\*\.task\_score | numeric | 
action\_result\.data\.\*\.report\.extracted\_files\.\*\.task\_uuid | string | 
action\_result\.data\.\*\.report\.format\.build\_version | numeric | 
action\_result\.data\.\*\.report\.format\.major\_version | numeric | 
action\_result\.data\.\*\.report\.format\.minor\_version | numeric | 
action\_result\.data\.\*\.report\.format\.name | string | 
action\_result\.data\.\*\.report\.malicious\_activity\.\*\.description | string | 
action\_result\.data\.\*\.report\.malicious\_activity\.\*\.type | string | 
action\_result\.data\.\*\.report\.md5 | string | 
action\_result\.data\.\*\.report\.mime\_type | string | 
action\_result\.data\.\*\.report\.score | numeric | 
action\_result\.data\.\*\.report\.uuid | string | 
action\_result\.summary\.id | string |  `lastline task id` 
action\_result\.summary\.result\_url | string |  `url`  `domain` 
action\_result\.summary\.score | numeric | 
action\_result\.summary\.target | string |  `file name` 
action\_result\.summary\.type | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate url'
Load a URL in the Lastline sandbox and retrieve the analysis results

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to detonate | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.activities\.\*\.desc | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.activities\.\*\.is\_test | boolean | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.activities\.\*\.name | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.activities\.\*\.score | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.activities\.\*\.version | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_length | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.content\_type | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.end | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.error | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.filename | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.parent\_url | string |  `url` 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.relation\_type | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.relation\_type\_str | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.start | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.status | numeric | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.task\_uuid | string | 
action\_result\.data\.\*\.report\.analysis\.network\.requests\.\*\.url | string |  `url` 
action\_result\.data\.\*\.report\.analysis\.result\.analysis\_ended | string | 
action\_result\.data\.\*\.report\.analysis\.result\.detector | string | 
action\_result\.data\.\*\.report\.analysis\.statics\.\*\.code | string | 
action\_result\.data\.\*\.report\.analysis\.statics\.\*\.media\_type | string | 
action\_result\.data\.\*\.report\.analysis\.statics\.\*\.source\_url | string | 
action\_result\.data\.\*\.report\.analysis\.strings\.\*\.str\_len | numeric | 
action\_result\.data\.\*\.report\.analysis\.strings\.\*\.str\_type | string | 
action\_result\.data\.\*\.report\.analysis\.strings\.\*\.value | string | 
action\_result\.data\.\*\.report\.analysis\.subject\.type | string | 
action\_result\.data\.\*\.report\.analysis\.subject\.url | string |  `url` 
action\_result\.data\.\*\.report\.analysis\_engine\_version | numeric | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.metadata\_type | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.name | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.retention\_date | string | 
action\_result\.data\.\*\.report\.analysis\_metadata\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.report\.format\.build\_version | numeric | 
action\_result\.data\.\*\.report\.format\.major\_version | numeric | 
action\_result\.data\.\*\.report\.format\.minor\_version | numeric | 
action\_result\.data\.\*\.report\.format\.name | string | 
action\_result\.data\.\*\.report\.malicious\_activity\.\*\.description | string | 
action\_result\.data\.\*\.report\.malicious\_activity\.\*\.type | string | 
action\_result\.data\.\*\.report\.prefilter\_scanners\.\*\.activity | string | 
action\_result\.data\.\*\.report\.prefilter\_scanners\.\*\.detector\_id | string | 
action\_result\.data\.\*\.report\.prefilter\_scanners\.\*\.score | numeric | 
action\_result\.data\.\*\.report\.prefilter\_scanners\.\*\.test | boolean | 
action\_result\.data\.\*\.report\.prefilter\_scanners\.\*\.version | numeric | 
action\_result\.data\.\*\.report\.prefilter\_score | numeric | 
action\_result\.data\.\*\.report\.score | numeric | 
action\_result\.data\.\*\.report\.uuid | string | 
action\_result\.summary\.id | string |  `lastline task id` 
action\_result\.summary\.result\_url | string |  `url`  `domain` 
action\_result\.summary\.score | numeric | 
action\_result\.summary\.target | string |  `file name` 
action\_result\.summary\.type | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'test connectivity'
This action connects to the server to verify the connection

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output

## action: 'get artifact'
Loads artifacts from Lastline and stores them in Vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Task ID to get the results of | string |  `lastline task id`
**artifact name** |  optional  | Name of the Artifact (when not specified all artifacts will be stored) | string |  `file name`
**password** |  optional  | Optional password for artifact encryption | string |  `password`
**container id** |  optional  | Optional container id for artifact storage (Is detected automatically) | number |  `container id`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `lastline task id`
action\_result\.parameter\.artifact_name | string |  `file name`
action\_result\.parameter\.password | string |  `password`
action\_result\.parameter\.container_id | number |  `container id` 
action\_result\.data\.\*\.timestamp | number | 
action\_result\.data\.\*\.metadata_type | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.retention_date | string | 
action\_result\.data\.\*\.source_file | string |  `file name`
action\_result\.data\.\*\.succeeded | boolean | 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.hash | string |  `file hash`
action\_result\.data\.\*\.vault_id | string |  `vault id`
action\_result\.data\.\*\.container | number |  `container id`
action\_result\.data\.\*\.size | number |  
action\_result\.data\.\*\.id | number |  `file id`
action\_result\.data\.\*\.created_via | string |
action\_result\.data\.\*\.task_id | string |  `lastline task id`
action\_result\.data\.\*\.file_name | string |  `file name`
action\_result\.data\.\*\.vault_state | string | 
action\_result\.summary\.id | string |  `lastline task id` 
action\_result\.summary\.result\_url | string |  `url`  `domain` 
action\_result\.summary\.type | string | 
action\_result\.summary\.artifacts_stored | numeric | 
action\_result\.summary\.artifacts_failed | numeric | 
action\_result\.summary\.artifacts_total | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |