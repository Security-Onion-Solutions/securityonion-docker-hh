#!/bin/bash

# Original Author: Josh Brower, Josh@DefensiveDepth.com
# Version: 2020.04.06-Rev1

# This script is licensed under the terms of the MIT license.

# This script is part of the Security Onion Fleet / Osquery integration.
# generate_packages.sh $Enroll_Secret $Fleet_Hostname $Package_version $Auto_update:disabled

# NOTE: All of the MSI filenames (fil*) will change when a new MSI has been generated with package-creator.exe 

###---Initial Prep
mkdir /etc/so-launcher
mkdir -p /var/launcher/{msi,deb,rpm,pkg}

#Set enroll secret
printf "$1" > src/config/secret

#Set hostname
sed -i 's@ninja@'"$2"'@' /var/launcher/src/config/launcher-msi.flags
sed -i 's@ninja@'"$2"'@' /var/launcher/src/config/launcher.flags

#If roots.pem exists, add flag & copy over it over to src
if [ -s /var/launcher/launcher.crt ] 
then
    printf "%s\n" "root_pem C:\Program Files\Kolide\Launcher-so-launcher\conf\roots.pem" >> src/config/launcher-msi.flags
    cp /var/launcher/launcher.crt msi/fil9DF688E35240EB6774DE8ECCC9A54A59
    
    printf "root_pem /etc/launcher/roots.pem\n" >> src/config/launcher.flags
    cp /var/launcher/launcher.crt /etc/so-launcher/roots.pem
else
    #deb & MSI packaging will likely fail without this
    touch /etc/so-launcher/roots.pem
    touch msi/fil9DF688E35240EB6774DE8ECCC9A54A59
fi

#Autoupdate is enabled by default, but can be disabled with "disabled" flag
if [ "$4" = "disabled" ]
then
    #autoupdate disabled - do not add autoupdate flags to flag file
    :
else
    printf "\nautoupdate\nupdate_channel stable\n" >> src/config/launcher-msi.flags
    printf "\nautoupdate\nupdate_channel stable\n" >> src/config/launcher.flags
fi

# Copy over edited config files - MSI
cp src/config/launcher-msi.flags msi/fil95753343B566BF4C16E76CDA6BC94D4A
cp src/config/launcher-msi.flags /output/launcher-msi.flags
cp src/config/secret msi/fil15D420E59F8659B73ED2575BF94D9F41

# Copy over edited config files - DEB/RPM/PKG
cp src/config/launcher.flags /etc/so-launcher/
cp src/config/launcher.flags /output/launcher.flags
cp src/config/secret /etc/so-launcher/

###---Start MSI rebuild
printf "Starting MSI rebuild...\n"

#Extract cab from msi
msidump -s -d msi src/packages/launcher.msi

# Extract non-config files from cab (osqueryd, launcher, launcher extension)
# These filenames will change when a new MSI is generated from package-creator
cabextract -d msi -F fil10D*  msi/_Streams/go.cab
cabextract -d msi -F fil21B*  msi/_Streams/go.cab
cabextract -d msi -F filC0D*  msi/_Streams/go.cab

#Create a new go.cab using the updated config files & just-extracted binaries
cd msi && gcab -vz -c go.cab fil* && cd ..

#Overwrite the old go.cab with the newly created one
msibuild src/packages/launcher.msi -a go.cab  msi/go.cab

#Copy the edited msi to the output folder
cp src/packages/launcher.msi /output/launcher.msi

printf "MSI rebuild complete\n"
###--- MSI rebuild Complete

###--- Start RPM rebuild
printf "Starting RPM rebuild...\n"

#Strip out flags & secret file from current rpm
fpm -n launcher-edited  -p rpm -x *etc* -t rpm -s rpm src/packages/launcher.rpm

#Rebuild rpm with new flags & secret
fpm -n launcher-final -v $3 -p rpm --config-files /etc/so-launcher -t rpm -s rpm rpm/launcher-edited*.rpm

#Copy the edited rpm to the output folder
cp rpm/launcher-final*.rpm /output/launcher.rpm

printf "RPM rebuild complete\n"
###--- RPM rebuild Complete


###--- Start DEB rebuild
printf "Starting DEB rebuild...\n"

#Strip out flags & secret file from current deb
fpm -n launcher-edited  -p deb -x *etc* -t deb -s deb src/packages/launcher.deb

#Rebuild deb with new flags & secret
fpm -n launcher-final -v $3 -p deb --config-files /etc/so-launcher -t deb -s deb deb/launcher-edited*.deb

#Copy the edited deb to the output folder
cp deb/launcher-final*.deb /output/launcher.deb

printf "DEB rebuild complete\n"
###--- DEB rebuild Complete
