import os

# Mail reporting
SG_USERNAME = os.environ.get('SG_USERNAME')
SG_PASSWORD = os.environ.get('SG_PASSWORD')

TO_EMAIL = [
    'infosec-audit+scoper@uber.com',
]
FROM_EMAIL = 'scoper@security.uber.com'
