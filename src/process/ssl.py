import ssl
import socket
import datetime

trusted_cas = ['GeoTrust', 'GoDaddy', 'Network Solutions', 'Thawte', 'Comodo', 'Doster', 'VeriSign']

def get_certificate_info(domain):
    try:
        context = ssl.create_default_context()
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        connection.connect((domain, 443))
        cert = connection.getpeercert()
        connection.close()
        
        issuer = dict(cert.get('issuer', []))
        notAfter = cert.get('notAfter')
        certificate_issuer = issuer.get('organizationName', 'Unknown')
        
        expiration_date = datetime.datetime.strptime(notAfter, "%b %d %H:%M:%S %Y GMT")
        
        today = datetime.datetime.utcnow()
        certificate_age = (today - expiration_date).days / 365  # age in years
        
        return certificate_issuer, certificate_age
    except Exception:
        return None, None