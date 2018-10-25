#!/bin/bash

git grep ^LIB_EXPORT $* | sed -e 's/[(\[].*//' -e 's/.* //' -e 's/^\*\{,2\}//'
