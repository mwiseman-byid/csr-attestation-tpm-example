from pyasn1.type import univ, namedtype, tag
import argparse
from pyasn1.codec.der.encoder import encode


class TcgAttestCertify(univ.Sequence):
    pass


TcgAttestCertify.componentType = namedtype.NamedTypes(
    namedtype.NamedType('attest', univ.OctetString()),
    namedtype.NamedType('signature', univ.OctetString()),
    namedtype.NamedType('public', univ.OctetString().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
)


parser = argparse.ArgumentParser()
parser.add_argument('attest', type=argparse.FileType('rb'))
parser.add_argument('signature', type=argparse.FileType('rb'))
parser.add_argument('public', type=argparse.FileType('rb'))

args = parser.parse_args()

certify_ext = TcgAttestCertify()
certify_ext['attest'] = args.attest.read()
certify_ext['signature'] = args.signature.read()
certify_ext['public'] = args.public.read()

print(certify_ext)

der = encode(certify_ext)

print(der.hex())
