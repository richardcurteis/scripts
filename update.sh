#!/bin/bash

infile=$0

while IFS= read -r line
do
  git clone $line
done
