import os

# Mail reporting
SG_USERNAME = os.environ.get('SG_USERNAME')
SG_PASSWORD = os.environ.get('SG_PASSWORD')

to_email = [
    'infosec-audit+scoper@uber.com',
]
from_email = 'scoper@security.uber.com'
