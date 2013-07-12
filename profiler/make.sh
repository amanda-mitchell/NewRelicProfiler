#!/bin/sh

gcc -shared -o libmono-profiler-newrelic.so newrelic.c `pkg-config --cflags --libs mono-2` -fPIC -std=c99 -lexpat

