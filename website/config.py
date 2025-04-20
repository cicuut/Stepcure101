import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
    MONGO_URI = os.environ.get('MONGO_URI') or 'mongodblink'
    MISP_URL = os.environ.get('MISP_URL') or 'mylocalhost'
    MISP_KEY = os.environ.get('MISP_KEY') or 'API_KEY'

    MISP_VERIFYCERT = False
 
