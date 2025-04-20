import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pymisp import PyMISP
from flask import current_app

MISP_URL = "https://192.168.56.101"
MISP_KEY = "API_KEY"
VERIFY_CERT = False

def fetch_recent_threats(limit=10):
    try:
        misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_CERT)

        # Fetch events with more details
        events = misp.search(controller='events', limit=limit, pythonify=True)
        
        if not events:
            print("⚠️ No threats found in MISP response.")
            return []

        threats = []
        for event in events:
            threat = {
                'id': event.id,
                'info': event.info,
                'threat_level': event.threat_level_id,
                'date': event.date,
                'tags': [tag.name for tag in event.tags],
                'attributes': []
            }
            
            for attribute in event.attributes:
                threat['attributes'].append({
                    'type': attribute.type,
                    'category': attribute.category,
                    'value': attribute.value
                })
            
            threats.append(threat)

        print(f"Fetched threats: {threats}")
        return threats

    except Exception as e:
        print(f"❌ Error connecting to MISP: {e}")
        return []

def calculate_risk(impact, likelihood):
    risk_matrix = {
        (1, 1): 'Low', (1, 2): 'Low', (1, 3): 'Moderate',
        (2, 1): 'Low', (2, 2): 'Moderate', (2, 3): 'High',
        (3, 1): 'Moderate', (3, 2): 'High', (3, 3): 'Critical'
    }
    return risk_matrix.get((impact, likelihood), 'Unknown')