#!/bin/sh

#with bad browser
#~/tor-browser_en-US/Browser/firefox -no-remote -profile ~/tor-browser_en-US/Data/Browser/testprofile google.ca

rm ~/test.torlog
rm ~/testdata.tbrlog
rm ~/test.tbrlog

TBRDIR=~/tor-browser-log-build/Browser
PREFDIR=$TBRDIR/TorBrowser/Data/Browser/9s7q826o.default
DATADIR=~/data/treebatch-compare

FTBRDIR=~/tor-browser-fix-build/Browser
FPREFDIR=$FTBRDIR/TorBrowser/Data/Browser/506ojrdt.default


filelist=()
while read line
do
filelist+=($line)
done < top-200-tree

ffilelist=()
while read line
do
ffilelist+=($line)
done < top-200-ftree

startsite=0
startind=0
maxsite=200
maxind=100
for (( j=$startind; j<$maxind; j++ ))
do
for (( i=0; i<$maxsite; i++ ))
do
	if ([ $i -lt $startsite ] && [ $j -eq $startind ])
	then
		continue
	fi
	echo $i, $j
	pname=${filelist[$i]}
	cp $PREFDIR/prefs.js.bak $PREFDIR/prefs.js
	timeout 60 $TBRDIR/firefox $pname
	rm ~/test.torlog
	mv ~/test.tbrlog $DATADIR/$i-$j-1.tbrlog
	time=`date +%s`
	echo $i,$j,1,$pname,$time >> $DATADIR/runtor-tree-4.log
	sleep 3

	pname=${filelist[$i]}
	cp $PREFDIR/prefs-nopipeline.js.bak $PREFDIR/prefs.js
	timeout 60 $TBRDIR/firefox $pname
	rm ~/test.torlog
	mv ~/test.tbrlog $DATADIR/$i-$j-2.tbrlog
	time=`date +%s`
	echo $i,$j,2,$pname,$time >> $DATADIR/runtor-tree-4.log
	sleep 3

	pname=${ffilelist[$i]}
	cp $FPREFDIR/prefs.js.bak $FPREFDIR/prefs.js
	timeout 60 $FTBRDIR/firefox $pname
	rm ~/test.torlog
	mv ~/test.tbrlog $DATADIR/$i-$j-3.tbrlog
	time=`date +%s`
	echo $i,$j,3,$pname,$time >> $DATADIR/runtor-tree-4.log
	sleep 3
done
done
