@load frameworks/intel/seen
@load frameworks/intel/do_notice
@load frameworks/files/hash-all-files

redef Intel::read_files += {
	"/opt/bro/share/bro/intel/intel.dat"
};
