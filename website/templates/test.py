from pymisp import PyMISP
import random

MISP_URL = "https://192.168.56.101"
MISP_KEY = "vKw9eWvfCil5HcSt0Q5nsJs0fOpmTCt5modKEsUp"
VERIFY_CERT = False

def create_event(misp, event_info, threat_level="High", date=None):
    """Function to create an event and add attributes to it"""
    event_data = {
        'info': event_info,           # Info about the event
        'threat_level_id': threat_level,  # Threat level for the event
        'date': date or '2025-01-30',   # Optional: Set date if available, else default
    }

    # Create event
    event = misp.add_event(**event_data)
    print(f"Created event with ID: {event['Event']['id']}")
    return event['Event']['id']

def create_attributes(misp, event_id, attributes_data):
    """Function to create attributes for an event"""
    for attribute in attributes_data:
        attribute_data = {
            'event_id': event_id,
            'type': attribute['type'],
            'category': attribute['category'],
            'value': attribute['value'],
            'to_ids': attribute.get('to_ids', False),
        }
        # Add attribute to the event
        misp.add_attribute(**attribute_data)
        print(f"Added attribute {attribute['type']} to event {event_id}")

def generate_fake_attributes():
    """Function to generate some random attributes for the event"""
    types = ['ip-src', 'ip-dst', 'url', 'domain', 'email-src']
    categories = ['Network activity', 'Payload delivery', 'Tactics', 'Indicators']
    values = ['192.168.1.1', 'http://example.com', 'user@example.com', 'malicious.com', 'payload']

    # Generate random attributes
    attributes = []
    for _ in range(5):  # Generate 5 attributes per event
        attribute = {
            'type': random.choice(types),
            'category': random.choice(categories),
            'value': random.choice(values),
            'to_ids': True
        }
        attributes.append(attribute)
    
    return attributes

def fetch_and_create_events():
    """Main function to fetch events and create them in MISP"""
    try:
        misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_CERT)

        # Example data for events (you can replace this with real data)
        events_data = [
            {'info': 'Event 1 - Cyber Attack', 'threat_level': 'High'},
            {'info': 'Event 2 - Phishing Attempt', 'threat_level': 'Medium'},
            {'info': 'Event 3 - Malware Detection', 'threat_level': 'Critical'},
        ]

        for event_data in events_data:
            event_id = create_event(misp, event_data['info'], event_data['threat_level'])
            attributes_data = generate_fake_attributes()  # Generate random attributes
            create_attributes(misp, event_id, attributes_data)

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    fetch_and_create_events()
