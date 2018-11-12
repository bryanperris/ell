#!/bin/bash

SOURCES=`ls ell/*.c`

echo -e "ELL_0.10 {"
echo -e "global:"

for i in $SOURCES ; do
	f=`basename $i .c`
	t=`ctags -x --c-kinds=fp $i | awk '/LIB_EXPORT/{ print $1 }'`
	if [ -n "$t" ] ; then
		echo -e "\t/* $f */"
		for n in $t ; do
			echo -e "\t$n;"
		done
	fi
done

echo -e "local:"
echo -e "\t*;"
echo -e "};"
