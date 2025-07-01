from flask import Flask, render_template, jsonify
from data import *
import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3
from dotenv import load_dotenv
import os
import select
import sys
import datetime