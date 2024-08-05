from flask import Flask, request, render_template_string
from werkzeug.utils import secure_filename
import os
import hashlib
import requests
from oletools.olevba import VBA_Parser
from PyPDF2 import PdfFileReader
from docx import Document
from pptx import Presentation
from bs4 import BeautifulSoup
import re
import filetype
import json
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
VIRUSTOTAL_API_KEY = ''

template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat and Malware Analysis Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
    <style>
        body {
            background-color: #1e1e1e;
            color: #dcdcdc;
            font-family: 'Arial', sans-serif;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #2a2a2a;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.6);
        }
        h1, h2 {
            color: #00bcd4;
            text-align: center;
            font-size: 2em;
        }
        form {
            display: flex;
            justify-content: center;
            margin-bottom: 30px;
        }
        input[type="file"] {
            margin-right: 10px;
            border: 1px solid #00bcd4;
            padding: 10px;
            border-radius: 4px;
            background-color: #333;
            color: #dcdcdc;
        }
        button {
            background-color: #00bcd4;
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        button:hover {
            background-color: #0097a7;
        }
        .section {
            margin-bottom: 40px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #444;
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #555;
        }
        .chart-container {
            width: 100%;
            height: 400px;
        }
        pre {
            background-color: #222;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .status-bar {
            height: 30px;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        .status-bar.red {
            background-color: #f44336;
        }
        .status-bar.yellow {
            background-color: #ffeb3b;
        }
        .status-bar.green {
            background-color: #4caf50;
        }
        .icon {
            font-size: 1.5em;
            margin-right: 8px;
        }
        #map {
            height: 400px;
            width: 100%;
            margin-bottom: 20px;
        }
        .vt-status-bar {
            height: 20px;
            border-radius: 4px;
            margin-bottom: 5px;
        }
        .threat-intel-table {
            background-color: #333;
            color: #dcdcdc;
        }
        .threat-intel-table td {
            border: 1px solid #444;
        }
        .threat-intel-table th {
            background-color: #555;
        }
        .engine-list {
            max-height: 400px;
            overflow-y: auto;
            padding: 10px;
            border: 1px solid #444;
            background-color: #333;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1><i class="fas fa-shield-alt"></i> Threat and Malware Analysis Dashboard</h1>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file" accept=".xls,.xlsm,.doc,.docx,.ppt,.pptx,.pdf" required>
            <button type="submit"><i class="fas fa-upload"></i> Upload & Scan</button>
        </form>
        {% if results %}
            <div class="section">
                <h2><i class="fas fa-info-circle"></i> Metadata</h2>
                <table>
                    <tr><th>Type</th><td>{{ results['metadata']['Type'] }}</td></tr>
                    <tr><th>Size</th><td>{{ results['metadata']['Size'] }}</td></tr>
                    <tr><th>Creation Date</th><td>{{ results['metadata']['Creation Date'] }}</td></tr>
                    <tr><th>Modification Date</th><td>{{ results['metadata']['Modification Date'] }}</td></tr>
                </table>
            </div>
            <div class="section">
                <h2><i class="fas fa-hashtag"></i> File Hashes</h2>
                <table>
                    <tr><th>Algorithm</th><th>Hash</th></tr>
                    <tr><td>MD5</td><td>{{ results['hashes']['md5'] }}</td></tr>
                    <tr><td>SHA-1</td><td>{{ results['hashes']['sha1'] }}</td></tr>
                    <tr><td>SHA-256</td><td>{{ results['hashes']['sha256'] }}</td></tr>
                </table>
            </div>
            <div class="section">
                <h2><i class="fas fa-code"></i> VBA/Macro Analysis</h2>
                <table>
                    <tr><th>Malicious</th><td>{{ results['vba_analysis']['malicious'] }}</td></tr>
                    <tr><th>Suspicious</th><td>{{ results['vba_analysis']['suspicious'] }}</td></tr>
                    <tr><th>Undetected</th><td>{{ results['vba_analysis']['undetected'] }}</td></tr>
                    <tr><th>Harmless</th><td>{{ results['vba_analysis']['harmless'] }}</td></tr>
                    <tr><th>Timeout</th><td>{{ results['vba_analysis']['timeout'] }}</td></tr>
                    <tr><th>Confirmed Timeout</th><td>{{ results['vba_analysis']['confirmed-timeout'] }}</td></tr>
                    <tr><th>Failure</th><td>{{ results['vba_analysis']['failure'] }}</td></tr>
                    <tr><th>Type Unsupported</th><td>{{ results['vba_analysis']['type-unsupported'] }}</td></tr>
                </table>
            </div>
            <div class="section">
                <h2><i class="fas fa-link"></i> Embedded Links</h2>
                <table>
                    <tr><th>Link</th><th>IP Address</th><th>Geo Location</th></tr>
                    {% for link in results['links'] %}
                        <tr>
                            <td>{{ link['url'] }}</td>
                            <td>{{ link['ip'] }}</td>
                            <td>{{ link['geo'] }}</td>
                        </tr>
                    {% endfor %}
                </table>
            </div>
            <div class="section">
                <h2><i class="fas fa-map-marker-alt"></i> Geo Location Map</h2>
                <div id="map"></div>
                <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
                <script>
                    var map = L.map('map').setView([0, 0], 2);
                    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                        maxZoom: 19
                    }).addTo(map);

                    var locations = {{ results['geo_locations']|tojson }};
                    locations.forEach(function(location) {
                        L.marker([location.lat, location.lng]).addTo(map)
                            .bindPopup(location.popup)
                            .openPopup();
                    });
                </script>
            </div>
            <div class="section">
                <h2><i class="fas fa-diagnoses"></i> VirusTotal Detected Engines</h2>
                <div class="engine-list">
                    {% if results['vt_engines'] %}
                        <table class="threat-intel-table">
                            <thead>
                                <tr><th>Engine Name</th><th>Result</th></tr>
                            </thead>
                            <tbody>
                                {% for engine in results['vt_engines'] %}
                                    <tr>
                                        <td>{{ engine['name'] }}</td>
                                        <td>{{ engine['result'] }}</td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% else %}
                        <p>No results from VirusTotal.</p>
                    {% endif %}
                </div>
            </div>
            <div class="section">
                <h2><i class="fas fa-chart-line"></i> File Analysis Report</h2>
                <div class="chart-container">
                    <canvas id="chart"></canvas>
                </div>
                <script>
                    var ctx = document.getElementById('chart').getContext('2d');
                    var chart = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: ['Malicious', 'Suspicious', 'Harmless'],
                            datasets: [{
                                label: 'VirusTotal Analysis Results',
                                data: [
                                    {% if results['vt_engines'] %}
                                        {{ results['vt_engines']|length }}
                                    {% else %}
                                        0
                                    {% endif %}
                                ],
                                backgroundColor: ['#f44336', '#ffeb3b', '#4caf50']
                            }]
                        },
                        options: {
                            responsive: true,
                            scales: {
                                x: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });
                </script>
            </div>
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Analyze file
            results = analyze_file(file_path)
            return render_template_string(template, results=results)
    return render_template_string(template, results=None)

def analyze_file(file_path):
    file_info = {
        'metadata': {
            'Type': 'Unknown',
            'Size': os.path.getsize(file_path),
            'Creation Date': datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
            'Modification Date': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
        },
        'hashes': {
            'md5': '',
            'sha1': '',
            'sha256': '',
        },
        'vba_analysis': {
            'malicious': 0,
            'suspicious': 0,
            'undetected': 0,
            'harmless': 0,
            'timeout': 0,
            'confirmed-timeout': 0,
            'failure': 0,
            'type-unsupported': 0,
        },
        'links': [],
        'geo_locations': [],
        'vt_engines': [],
    }

    # Calculate hashes
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    
    file_info['hashes']['md5'] = md5.hexdigest()
    file_info['hashes']['sha1'] = sha1.hexdigest()
    file_info['hashes']['sha256'] = sha256.hexdigest()

    # VBA/Macro Analysis
    if file_path.endswith(('.doc', '.docx')):
        try:
            doc = Document(file_path)
            for para in doc.paragraphs:
                # Check for malicious patterns
                if re.search(r'\b(?:macro|vba|script)\b', para.text, re.IGNORECASE):
                    file_info['vba_analysis']['suspicious'] += 1
        except Exception as e:
            file_info['vba_analysis']['failure'] += 1

    # VirusTotal Analysis
    vt_result = get_virustotal_results(file_info['hashes']['sha256'])
    if vt_result:
        file_info['vt_engines'] = vt_result.get('detected_engines', [])

    return file_info

def get_virustotal_results(file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        detected_engines = []
        if 'data' in data and 'attributes' in data['data'] and 'last_analysis_results' in data['data']['attributes']:
            for engine, result in data['data']['attributes']['last_analysis_results'].items():
                detected_engines.append({'name': engine, 'result': result['result']})
        return {'detected_engines': detected_engines}
    return None

if __name__ == '__main__':
    app.run(debug=True)
