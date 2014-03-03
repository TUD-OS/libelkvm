#!/bin/bash
autoreconf --install || exit 1
./configure
