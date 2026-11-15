"""
A simple client that uses the Python ACME library to run a test issuance and
revocation against a local Pebble server, and checks Pebble's CRL. Unlike
chisel.py this version implements the most recent version of the ACME
specification.

Pebble must have CRLs enabled, preferably with no delay:

$ PEBBLE_CRL_MAX_DELAY=0 pebble -config test/config/pebble-config-crl.json

Usage:

$ virtualenv venv
$ . venv/bin/activate
$ pip install -r requirements.txt
$ python chisel2.py foo.com bar.com
"""
from __future__ import print_function
import logging
import os
import ssl
import sys
import signal
import threading
import time

import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes

import OpenSSL
import josepy

from acme import challenges
from acme import client as acme_client
from acme import crypto_util as acme_crypto_util
from acme import errors as acme_errors
from acme import messages
from acme import standalone

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(int(os.getenv('LOGLEVEL', 0)))

DIRECTORY = os.getenv('DIRECTORY', 'https://localhost:14000/dir')
ACCEPTABLE_TOS = os.getenv('ACCEPTABLE_TOS',"data:text/plain,Do%20what%20thou%20wilt")
PORT = os.getenv('PORT', '5002')

# How long to wait for a revocation to appear on the CRL. Pebble delays CRL
# entries by up to PEBBLE_CRL_MAX_DELAY seconds (15 by default).
CRL_WAIT = float(os.getenv('CRL_WAIT', '20'))

# URLs to control dns-test-srv
SET_TXT = "http://localhost:8055/set-txt"
CLEAR_TXT = "http://localhost:8055/clear-txt"

def wait_for_acme_server():
    """Wait for directory URL set in the DIRECTORY env variable to respond"""
    while True:
        try:
            if requests.get(DIRECTORY).status_code == 200:
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.1)

def make_client(email=None):
    """Build an acme.Client and register a new account with a random key."""
    key = josepy.JWKRSA(key=rsa.generate_private_key(65537, 2048, default_backend()))

    net = acme_client.ClientNetwork(key, user_agent="Boulder integration tester")
    directory = messages.Directory.from_json(net.get(DIRECTORY).json())
    client = acme_client.ClientV2(directory, net)
    tos = client.directory.meta.terms_of_service
    if tos == ACCEPTABLE_TOS:
        net.account = client.new_account(messages.NewRegistration.from_data(email=email,
            terms_of_service_agreed=True))
    else:
        raise Exception("Unrecognized terms of service URL %s" % tos)
    return client

def get_chall(authz, typ):
    for chall_body in authz.body.challenges:
        if isinstance(chall_body.chall, typ):
            return chall_body
    raise Exception("No %s challenge found" % typ)

class ValidationError(Exception):
    """An error that occurs during challenge validation."""
    def __init__(self, domain, problem_type, detail, *args, **kwargs):
        self.domain = domain
        self.problem_type = problem_type
        self.detail = detail

    def __str__(self):
        return "%s: %s: %s" % (self.domain, self.problem_type, self.detail)

def make_csr(domains):
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    return acme_crypto_util.make_csr(pem, domains, False)

def http_01_answer(client, chall_body):
    """Return an HTTP01Resource to server in response to the given challenge."""
    response, validation = chall_body.response_and_validation(client.net.key)
    return standalone.HTTP01RequestHandler.HTTP01Resource(
          chall=chall_body.chall, response=response,
          validation=validation)

def auth_and_issue(domains, chall_type="http-01", email=None, cert_output=None, client=None):
    """Make authzs for each of the given domains, set up a server to answer the
       challenges in those authzs, tell the ACME server to validate the challenges,
       then poll for the authzs to be ready and issue a cert."""
    if client is None:
        client = make_client(email)

    csr_pem = make_csr(domains)
    order = client.new_order(csr_pem)
    authzs = order.authorizations

    if chall_type == "http-01":
        cleanup = do_http_challenges(client, authzs)
    elif chall_type == "dns-01":
        cleanup = do_dns_challenges(client, authzs)
    else:
        raise Exception("invalid challenge type %s" % chall_type)

    try:
        order = client.poll_and_finalize(order)
    finally:
        cleanup()

    return order

def do_dns_challenges(client, authzs):
    cleanup_hosts = []
    for a in authzs:
        c = get_chall(a, challenges.DNS01)
        name, value = (c.validation_domain_name(a.body.identifier.value),
            c.validation(client.net.key))
        cleanup_hosts.append(name)
        requests.post(SET_TXT, json={
            "host": name + ".",
            "value": value
        }).raise_for_status()
        client.answer_challenge(c, c.response(client.net.key))
    def cleanup():
        for host in cleanup_hosts:
            requests.post(CLEAR_TXT, json={
                "host": host + "."
            }).raise_for_status()
    return cleanup

def do_http_challenges(client, authzs):
    port = int(PORT)
    challs = [get_chall(a, challenges.HTTP01) for a in authzs]
    answers = set([http_01_answer(client, c) for c in challs])
    server = standalone.HTTP01Server(("", port), answers)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()

    # cleanup has to be called on any exception, or when validation is done.
    # Otherwise the process won't terminate.
    def cleanup():
        server.shutdown()
        server.server_close()
        thread.join()

    try:
        # Loop until the HTTP01Server is ready.
        while True:
            try:
                if requests.get("http://localhost:{0}".format(port)).status_code == 200:
                    break
            except requests.exceptions.ConnectionError:
                pass
            time.sleep(0.1)

        for chall_body in challs:
            client.answer_challenge(chall_body, chall_body.response(client.net.key))
    except Exception:
        cleanup()
        raise

    return cleanup

def expect_problem(problem_type, func):
    """Run a function. If it raises a ValidationError or messages.Error that
       contains the given problem_type, return. If it raises no error or the wrong
       error, raise an exception."""
    ok = False
    try:
        func()
    except ValidationError as e:
        if e.problem_type == problem_type:
            ok = True
        else:
            raise
    except messages.Error as e:
        if problem_type in e.__str__():
            ok = True
        else:
            raise
    if not ok:
        raise Exception('Expected %s, got no error' % problem_type)

def load_cert(order):
    """Return the leaf and issuer certificates from a finalized order."""
    certs = x509.load_pem_x509_certificates(order.fullchain_pem.encode())
    return certs[0], certs[1]

def revoke(client, cert, reason):
    """Revoke cert, a cryptography x509.Certificate, with the given reason."""
    if hasattr(josepy, 'ComparableX509'):
        # Older acme releases (with josepy < 2) take a pyOpenSSL certificate
        # wrapped in josepy.ComparableX509.
        cert = josepy.ComparableX509(OpenSSL.crypto.X509.from_cryptography(cert))
    client.revoke(cert, reason)

def crl_url(cert):
    """Return the CRL distribution point URL from a certificate."""
    crldp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    return crldp.value[0].full_name[0].value

def fetch_revoked_entry(cert, issuer):
    """Fetch the CRL named in cert's CRLDP, check its signature against issuer,
       and poll until cert's entry appears. Return the entry."""
    url = crl_url(cert)
    deadline = time.time() + CRL_WAIT
    while True:
        resp = requests.get(url)
        resp.raise_for_status()
        crl = x509.load_der_x509_crl(resp.content)
        if not crl.is_signature_valid(issuer.public_key()):
            raise Exception("CRL from %s has an invalid signature" % url)
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if entry is not None:
            return entry
        if time.time() > deadline:
            raise Exception("serial %x not on CRL %s after %ss" % (cert.serial_number, url, CRL_WAIT))
        time.sleep(1)

def revoke_and_check_crl(domains):
    """Issue and revoke a certificate with keyCompromise, then check that it
       appears on the CRL with that reason. Also check that Pebble rejects a
       certificateHold revocation."""
    client = make_client()
    cert, issuer = load_cert(auth_and_issue(domains, client=client))
    revoke(client, cert, 1)
    entry = fetch_revoked_entry(cert, issuer)
    reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
    if reason != x509.ReasonFlags.key_compromise:
        raise Exception("CRL entry has reason %s, want keyCompromise" % reason)
    print("Revoked serial %x found on CRL %s" % (cert.serial_number, crl_url(cert)))

    # Use a new account, since Pebble may reuse the first account's valid
    # authorizations, which auth_and_issue doesn't handle.
    held_client = make_client()
    held, _ = load_cert(auth_and_issue(domains, client=held_client))
    expect_problem("urn:ietf:params:acme:error:badRevocationReason",
        lambda: revoke(held_client, held, 6))

if __name__ == "__main__":
    # Die on SIGINT
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    domains = sys.argv[1:]
    if len(domains) == 0:
        print(__doc__)
        sys.exit(0)
    try:
        wait_for_acme_server()
        revoke_and_check_crl(domains)
    except messages.Error as e:
        print(e)
        sys.exit(1)
