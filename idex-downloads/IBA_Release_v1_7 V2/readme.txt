-----------------------------------------------------------------------------------------------------------------------
IDEX TrustedBio IBA V 1.7 V2 (2023 December 20)
-----------------------------------------------------------------------------------------------------------------------

I. Changelog

 1. IBA_Applet_Integration_Guide v1.0.pdf

	- See change history in document.

II. List of Deliverables

  +-- readme.txt -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -> Releases Information (this file).
  +-- IBA_Applet_Integration_Guide v1.0.pdf -  -  -  -  -  -  -  -  -> Documentation
  |
  +-- iba  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -> IBA package
  |   +-- applet -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -> Built applets
  |   +-- doc -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -> Java doc
  |   +-- script -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -> Jcshell example scripts
  |   +-- share  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -> Java card Libraries
  +-- ibaclient  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -> IBA client example package
  |   +-- applet -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -> Built applets
  |   +-- script -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -> jcshell example scripts
  |   +-- src -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -> Example source code


-----------------------

NOTE: these instructions require that JCShell is installed and configured

1. Install and Personalise the IBA applet and Install the IBAClient applet
    a. Navigate to <install folder>/ibaclient/script
    b. update 82_Perso_IBA_Applet_AID.jcsh based on needs.  
           Existing one is only a demo sample, not covering all test scenarios.
           So please update this script to personalize IBA instance correctly.
    c. To install the applets/instances, including personalising the IBA applet instance 
       for use the with AID  of the IBAClient instance, run:
       > jcshell -f onestop.jcsh
       It will install one IBA instance and two IBAClient Instance by default.

2. Use IBA applet for Enroll over APDU interface
    a. Navigate to <install folder>/ibaclient/script
    b. Execute this script to perform the Enroll:
       > jcshell -f 83_Enroll_IBA_Applet.jcsh
    b. Execute this script to perform the Enroll Qualification:
       > jcshell -f 104_EnrollQualification.jcsh.jcsh

3. Use IBAClient applet for Enroll and Match over Shareable interface
    a. Navigate to <install folder>/ibaclient/script
    b. Execute this script to perform the Enroll:
       > jcshell -f 103_SingleEnroll_qual.jcsh
    c. Execute this script to perform a Match:
       > jcshell -f 108_match.jcsh