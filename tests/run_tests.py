#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Proxy loader for root run_tests.py
"""
import os
import sys

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, root_dir)

if __name__ == "__main__":
    import run_tests
    run_tests.main()
