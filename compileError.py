from pyasn1.type import univ, char, namedtype, constraint
from pyasn1_alt_modules import rfc5280

# EvidenceBundle ::= SEQUENCE
# {
#   evidence OCTET STRING,
#   certs SEQUENCE SIZE (1..10) OF Certificate OPTIONAL
# }
class EvidenceenceBundle(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('evidence', univ.OctetString),
        namedtype.OptionalNamedType('certs', univ.SequenceOf(
            componentType = rfc5280.Certificate(),
            subtypeSpec = constraint.ValueSizeConstraint(1, 10)
        ))
    )



# Traceback (most recent call last):
#   File "/home/mike/git/ietf/csr-attestation-tpm-example/compileError.py", line 9, in <module>
#     class EvidenceenceBundle(univ.Sequence):
#   File "/home/mike/git/ietf/csr-attestation-tpm-example/compileError.py", line 10, in EvidenceenceBundle
#     componentType = namedtype.NamedTypes(
#   File "/home/mike/.local/lib/python3.10/site-packages/pyasn1/type/namedtype.py", line 159, in __init__
#     self.__tagToPosMap = self.__computeTagToPosMap()
#   File "/home/mike/.local/lib/python3.10/site-packages/pyasn1/type/namedtype.py", line 253, in __computeTagToPosMap
#     for _tagSet in tagMap.presentTypes:
# AttributeError: 'property' object has no attribute 'presentTypes'