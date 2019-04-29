#!/bin/bash

#Original Author: Josh Brower, Josh@DefensiveDepth.com
#Version: 2019.04.03-Rev1

#This script is licensed under the terms of the MIT license.

#This script is part of the launcher-packager container.

###---Initial Prep
mkdir /etc/launcher
mkdir -p /var/launcher/{msi,deb,rpm,pkg}

#Update enroll secret - using @ delimeters because secret can contain /+
#sed -i 's@secret@'"$1"'@' src/config/secret
printf "$1" > src/config/secret

#Update hostname
sed -i 's@ninja@'"$2"'@' /var/launcher/src/config/launcher-msi.flags
sed -i 's@ninja@'"$2"'@' /var/launcher/src/config/launcher.flags

#If roots.pem exists, add flag & copy over it over to src
if [ -s /var/launcher/launcher.crt ] 
then
    printf "%s\n" "root_pem C:\Program Files\Kolide\Launcher-launcher\conf\roots.pem" >> src/config/launcher-msi.flags
    cp /var/launcher/launcher.crt msi/fil61BEFB046816E66FFC69B5A2B0F10704
    
    printf "root_pem /etc/launcher/roots.pem\n" >> src/config/launcher.flags
    cp /var/launcher/launcher.crt /etc/launcher/roots.pem
else
    #deb & MSI packaging will likely fail without this
    touch /etc/launcher/roots.pem
    touch msi/fil61BEFB046816E66FFC69B5A2B0F10704
fi

#Autoupdate is enabled by default, but can be disabled with "disabled" flag
if [ "$3" = "disabled" ]
then
    #autoupdate disabled - do not add autoupdate flags to flag file
    :
else
    printf "autoupdate\nupdate_channel stable\n" >> src/config/launcher-msi.flags
    printf "autoupdate\nupdate_channel stable\n" >> src/config/launcher.flags
fi

#Copy over edited config files
cp src/config/launcher-msi.flags msi/fil2D6AA082EFCB559A36C9A1939CD0F5A6
cp src/config/launcher-msi.flags /output/launcher-msi.flags
cp src/config/secret msi/fil65D833A357F62546DF7DC5CD82053062

cp src/config/launcher.flags /etc/launcher/
cp src/config/launcher.flags /output/launcher.flags
cp src/config/secret /etc/launcher/

###---Start MSI rebuild
printf "Starting MSI rebuild...\n"

#Extract cab from msi
msidump -s -d msi src/packages/launcher.msi

#Extract non-config files from cab
cabextract -d msi -F fil189*  msi/_Streams/go.cab
cabextract -d msi -F filAB0*  msi/_Streams/go.cab
cabextract -d msi -F filBDF*  msi/_Streams/go.cab

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
fpm -n launcher-final -p rpm --config-files /etc/launcher -t rpm -s rpm rpm/launcher-edited*.rpm

#Copy the edited rpm to the output folder
cp rpm/launcher-final*.rpm /output/launcher.rpm

printf "RPM rebuild complete\n"
###--- RPM rebuild Complete


###--- Start DEB rebuild
printf "Starting DEB rebuild...\n"

#Strip out flags & secret file from current deb
fpm -n launcher-edited  -p deb -x *etc* -t deb -s deb src/packages/launcher.deb

#Rebuild deb with new flags & secret
fpm -n launcher-final -p deb --config-files /etc/launcher -t deb -s deb deb/launcher-edited*.deb

#Copy the edited deb to the output folder
cp deb/launcher-final*.deb /output/launcher.deb

printf "DEB rebuild complete\n"
###--- DEB rebuild Complete
