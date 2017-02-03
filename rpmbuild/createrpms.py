#
# Script to build RPM's using latest LIS code, it will build the RPM's and copy it to LISISO folder
# currently we have two source tree one for RHEL 5 and one for RHEL6 
#
#
import os 
import sys
import shutil
import subprocess

homedir = os.getcwd()
directory = "lis-next"
if os.path.exists(directory):
 shutil.rmtree(directory)

def run(cmd):
 output = subprocess.call(cmd,shell=True)
 return output

# Clean up LISISO direcotry
#print "Cleaning up LISISO direcroty"
#run("./cleanupISODir.sh")


def buildrhel5():
 print "Cleaning up LISISO direcroty"
# run("./cleanupISODir5.sh")
 os.makedirs(directory)
 run("git clone https://github.com/LIS/lis-next")
 os.chdir(directory+"/hv-rhel5.x/")
 run("git checkout 4.1.3")
 run("tar -cvzf lis-next-rh5.tar.gz hv")
 shutil.copy("lis-next-rh5.tar.gz" , homedir+"/rh5/SOURCES/")
 os.chdir(homedir)
 shutil.rmtree(directory)
 found = False

 rhel5buildpath = homedir+"/rh5/pbuild"
 pbuildconfigfile = homedir+"/rh5/pbuild/.pbuild"
 pbuildMakefile = homedir+"/rh5/pbuild/Makefile"
 shutil.copy(pbuildconfigfile , "/root/")
 with open("/root/.pbuild", "a") as file:
    file.write("logdir: "+homedir+"/BuilgLogDir/rh5")
 with open(pbuildMakefile, "r") as myfile:
  for line in myfile :
   if "homedir=" in line:
    found = True
 if not found:
  with open(pbuildMakefile, "a") as myfile:
   myfile.write("homedir="+homedir)


 # Change direcoty to buildpath, before building .
 os.chdir(rhel5buildpath)

 # Now clean the destination VM's .
 clean = run("make clean")
 if clean :
  print "make clean failed"
  sys.exit(1)
 send = run("make send")
 if send :
  print "make send failed"
  sys.exit(1)
 make = run("make")
 if make :
  print "make failed"
  sys.exit(1)
 os.remove("/root/.pbuild")
 os.chdir(homedir)
# run("./copyallrpmsrhel5.sh")

def buildrhel6():
 print "Cleaning up LISISO direcroty"
# run("./cleanupISODir6.sh")
 os.makedirs(directory)
 run("git clone https://github.com/LIS/lis-next")
 os.chdir(directory+"/hv-rhel6.x/")
 run("git checkout 4.1.3")
 run("tar -cvzf lis-next-rh6.tar.gz hv")
 shutil.copy("lis-next-rh6.tar.gz" , homedir+"/rh6/SOURCES/")
 os.chdir(homedir)
 shutil.rmtree(directory)
 found = False

 rhel6buildpath=homedir+"/rh6/pbuild"
 pbuildconfigfile=homedir+"/rh6/pbuild/.pbuild"
 shutil.copy(pbuildconfigfile , "/root/")
 with open("/root/.pbuild", "a") as file:
    file.write("logdir: "+homedir+"/BuilgLogDir/rh6")
 pbuildMakefile = homedir+"/rh6/pbuild/Makefile"
 with open(pbuildMakefile, "r") as myfile:
  for line in myfile :
   if "homedir=" in line:
    found = True
 if not found:
  with open(pbuildMakefile, "a") as myfile:
   myfile.write("homedir="+homedir)

 # Change direcoty to buildpath, before building . 
 os.chdir(rhel6buildpath)
 
 # Now clean the destination VM's .
 clean = run("make clean")
 if clean : 
  print "make clean failed"
  sys.exit(1)
 send = run("make send")
 if send : 
  print "make send failed"
  sys.exit(1)
 make = run("make")
 if make : 
  print "make failed"
  sys.exit(1)
 os.remove("/root/.pbuild")
 os.chdir(homedir)
 #run("./copyallrpmsrhel6.sh")


def buildrhel7():
 print "Cleaning up LISISO direcroty"
# run("./cleanupISODir7.sh")
 os.makedirs(directory)
 run("git clone https://github.com/LIS/lis-next")
 os.chdir(directory+"/hv-rhel7.x/")
 run("git checkout 4.1.3")
 run("tar -cvzf lis-next-rh7.tar.gz hv")
 shutil.copy("lis-next-rh7.tar.gz" , homedir+"/rh7/SOURCES/")
 os.chdir(homedir)
 shutil.rmtree(directory)
 found = False

 rhel7buildpath = homedir+"/rh7/pbuild"
 pbuildconfigfile = homedir+"/rh7/pbuild/.pbuild"
 shutil.copy(pbuildconfigfile , "/root/")
 with open("/root/.pbuild", "a") as file:
  file.write("logdir: "+homedir+"/BuilgLogDir/rh7")
 pbuildMakefile = homedir+"/rh7/pbuild/Makefile"
 with open(pbuildMakefile, "r") as myfile:
  for line in myfile :
   if "homedir=" in line:
    found = True
 if not found:
  with open(pbuildMakefile, "a") as myfile:
   myfile.write("homedir="+homedir)

 # Change direcoty to buildpath, before building .
 os.chdir(rhel7buildpath)

 # Now clean the destination VM's .
 clean = run("make clean")
 if clean :
  print "make clean failed"
  sys.exit(1)
 send = run("make send")
 if send :
  print "make send failed"
  sys.exit(1)
 make = run("make")
 if make :
  print "make failed"
  sys.exit(1)
 os.remove("/root/.pbuild")
 os.chdir(homedir)
 #run("./copyallrpmsrhel7.sh")
 

### Main entry for script.###

def main(argv):
 for arg in sys.argv:
   if  arg == "rh5":
    print "RHEL5 Build initializing...."
    buildrhel5()
   elif arg == "rh6":
    print "RHEL6 Build initializing...."
    buildrhel6()
   elif  arg == "rh7":
    print "RHEL7 Build initializing...."
    buildrhel7()
   elif arg == "all":
    print "RHEL5 , RHEL6 and RHEL 7  Build initializing...."
    buildrhel5()
    buildrhel6()
    buildrhel7()
   elif len(sys.argv) == 1:
    print "USAGE :  createrpms.py <rh5 , rh6 or all>"
    sys.exit(2)
 # Tar the LISISO directory  .
 #run("tar -cvzf lis-rpms-autogen.tar.gz LISISO")

if __name__ == "__main__":
   main(sys.argv[1:])

