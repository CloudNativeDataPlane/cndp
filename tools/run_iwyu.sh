#
# $1 argument is the name of the build directory, so 'make rebuild' and then use 'builddir' as the
# argument to this script.
iwyu_tool -v -j 16 -p $1 > iwyu.txt
(cd $1; fix_include -b --comments < ../iwyu.txt)
rm iwyu.txt
