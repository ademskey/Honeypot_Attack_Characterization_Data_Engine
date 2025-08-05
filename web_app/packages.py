from flask import Flask, render_template, jsonify, request
import pandas as pd
import numpy as np
import warnings
from pandas.errors import PerformanceWarning
import threading
import time
import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3
from dotenv import load_dotenv
import os
import select
import sys
import datetime
from datetime import timezone
import matplotlib.pyplot as plt
import ast
import ipaddress