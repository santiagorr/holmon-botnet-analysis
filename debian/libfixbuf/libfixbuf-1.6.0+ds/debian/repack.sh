#!/bin/sh -e

if [ "$#" -ne "3" ] ; then
	echo "usage: $0 --upstream-version VERSION FILENAME"
	exit 1
fi

upstream_version="$2"
downloaded_file="$3"

# remove file matching *pyfixbuf* from upstream tarball without unpacking it
tarball=${downloaded_file%.gz}
gzip -cd "$downloaded_file" > "$tarball"
# searching for pyfixbuf because we can't know it's version
pyfixbuf=`tar --list --file "$tarball" | grep pyfixbuf`
tar --delete --file "$tarball" "$pyfixbuf"
# deleting docs as we will regenerate them
tar --delete --file "$tarball" "libfixbuf-$upstream_version/doc/html/"
# unfortunately this last step removes the magic number from the file header
# indicating that it is a gzip compressed tarball
gzip -c "$tarball" > "$downloaded_file"
rm -f "$tarball"
