#!/bin/bash

# Simple script to iterate through encoded QPACK files and decode them.
#
# Requires:
#   * a qpack-decoder binary
#   * a clone of https://github.com/qpackers/qifs in this directory


mkdir -p decoded

for f in qifs/encoded/qpack-06/*/*; do
  IFS='/' read -ra path <<< "$f"

  vendor=${path[3]}

  name=`basename "$f"`
  IFS='.' read -ra params <<< "$name"
  [ "${params[1]}" = "out" ] || continue
  prefix=${params[0]}

  echo "decoding ${name}"

  decoded_output_file="decoded/canonical-output-${vendor}-${name}"

  target/debug/qpack-decode $f > "decoded/temp-decoded"

  qifs/bin/sort-qif.pl --strip-comments "decoded/temp-decoded" > $decoded_output_file

  diff -u "qifs/qifs/$prefix.qif" "${decoded_output_file}"
  if [ $? -ne 0 ]; then
    echo "decoding ${f} failed!"
    exit
  fi
done

rm "decoded/temp-decoded"