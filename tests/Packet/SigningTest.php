<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Packet\PacketList;
use OpenPGP\Packet\PublicKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for Signature packet.
 */
class SigningTest extends OpenPGPTestCase
{
    const PASSPHRASE = 'password';
    const LITERAL_TEXT = 'Hello PHP PG';

    private static $rsaPublicKeyData = <<<EOT
BGRUrD4BCACe8iv48dGvqnbOuPv1DnnrasH/NZ5bbpGHW0gSOXb4p2d7VcfA6hfoyq1yEuZ2VDzJ
WpkhVnKMF1Ytj7d8mtnGsTQ6NfGrV9jRhGIxAYIgiDjzuhIejzMrTR/RAh9aARPTuEayRXoShTEg
cQfZxIQKwwU5hE4PDZFhq0h/T83eImWidUZwt3zw6jWq29nDtmtR96x+xznG0utZrHsbkxNtuLpX
YlrMl9Lcz9vbntpK45aq35P3cfg5UEjCLj1TAq6LPFnfiwbQcNkbsTRsxPqWpX4J6v5ZabJIFGyd
K14eiohYTbp7Uvr/e3yRhTirWYz4KnJwuFOsemuSjSAGi3C5ABEBAAE=
EOT;

    private static $dsaPublicKeyData = <<<EOT
BGRUrHERCAC/HCRsyTviyCVlaBWmhJoSZtmR0SzXjgyd6jbNeQLN4o58oCdUXN1o4aUG3dFmx6ed
BOIfpOeEgpnELVIvkxtAL5gV1aueOw+On3BeP+ZLtU0E60mDAa0rqCMgZrJLh8vlwaNI0HXNLgFZ
nyRHFK3Xng8h35MBr5vqXtsjVk+R0SiBikTcI+RmjwprM4rest/RxzYGyQeMm7dn4c8/9jg/ApQP
Dnk6tFyWTpsDhu7oei6Ko4zqPbx5/miRLdPhx96Bwionq9OCZHp3tYV7J+5M+R3ib2YAKTtLjgpQ
O/nSCi5VQ2HS0UnPPUqGRXJj/OS2vfJgOnB0V5IyYW0+lewbAQC6+kGApO0lWTCcu8R02V70XumX
zhoU+Y2UW7s3MjHNswgAkxOXHQBj3khAolVav1hFC/B34xeiTp7n7OFrNmUm7srE/iXouumXT3JS
VRRtnNTVZIH4gYoKLMUM0RkFrlctnxdgoG4Q6g5JTYvzc0OTTo6Dk2BgH4gCjr0eC7010dHusD8Z
v1dI21943lRHxTGAaYZ6VDv25NiVOIht2B1w07V0L+uxhYzffBUvu3JxAhkl/MVJahA/CkHpJNZE
MDMtxUtfS5ck0p+SrfbTdM3PNLNdhgqH8jsKUnNhoCN3jb1NbhmVjeQjJxi4s2yVw1s6gjkDcQxE
964yC2H9d+OEAEj9kxF4Qk2JJGK6UlLF/YkL6A3B7H/ddteIEiJ2gtOXvgf/e4n/51F40ue4Di90
iPA44CKJVZA30/t5O+CW+1T/uuPwyWKV/oZe9sCf4G0NsGSAeELJyFo0gyHXl+qnkGNBqYsBGzBe
yPYtKZ4PriDYhpwvy7gm6jPTgMjDjOrVuTZFuc6c1aUg6IczjSbnKhWVjU/Fv1NXwdH00vzMvqbM
Hju+d6L8bbegHjL2NkxmB6xDrJu21cWaK9udhUvCbQlMKsUYHbmW6heCSURoc1+WAzjRlOGysZOu
JN3kg8cu61aYn2FKiZDRQEDbHFVHJ52e34OZAmmWZLvzUk11E7dQdnpItffEwp8aGro7pUwGo79k
2R6iMnzQc3iIUX0Ns/vE3A==
EOT;

    private static $ecdsaP384PublicKeyData = <<<EOT
BGRYd7UTBSuBBAAiAwME3Z/lmJrDGnYHvT7xe5ei8xFfsCsrH+6AjmSftcJEYCCTy4CupXlvp5wb
FLQ2klduC2c09LzjULVFn4uQKdMacYb7X0UjI2q6MLGP1fpmg7mq4F8myVJx6lkvpHK44xDh
EOT;

    private static $ecdsaBrainpoolPublicKeyData = <<<EOT
BGRYXMETCSskAwMCCAEBBwIDBHKh5xdXoTfino6vulZBw4fl5lMtKgzXIeG9zhJuBInpE7gOlxes
07/JY2b9aIUph0fAku1xE+ljP5I/5pI5qrQ=
EOT;

    private static $eddsaCurve25519PublicKeyData = <<<EOT
BGRYXQUWCSsGAQQB2kcPAQEHQLvR0VoiVSt3+xzxSSQrR7/yrMzQG8OXueMhIkQb0UPM
EOT;

    public function testVerifyRsaSignature()
    {
        $signatureData = <<<EOT
iQEzBAEBCAAdFiEE/FAE35RzJ3EH6qYFGE0NxPXFMrIFAmRh15wACgkQGE0NxPXF
MrKIiAf/eF+pKn0r+5lr1vljCPizhGbMDj5Q8SQkX/JmhD523lzZh1XngJJGyonv
DA4Vbu296aJZYhsgFKBlRzOQb6oSYN9qSXiWayNVI5pgTIK+kZnCa/e528JMDsdo
vJjdpBj+LWR9e330MWcxUSh7EX8d0yl/SLkM4v/tMPehNFggMbiyKWJmFprzV4ft
/BQRgJfr7uWzO2W+mXc6McKey6bKAOAyt3hH8nNpBUden7DRzvUO2ebHZq723DCD
5eUCaFbxpwnuKKRXKOCJ+JTS9fPkoXpA/Lwh7zDdx8cuVkcQG0g4CrEU2uoOtW/h
Vz4AQHHwYBHm0u5+yiLZRMi3XYCtCA==
EOT;

        $publicKey = PublicKey::fromBytes(base64_decode(self::$rsaPublicKeyData));
        $packets = PacketList::decode(base64_decode($signatureData));
        $signature = $packets->offsetGet(0);
        $this->assertTrue($signature->verify($publicKey, self::LITERAL_TEXT));
    }

    public function testVerifyDsaSignature()
    {
        $signatureData = <<<EOT
iHUEAREIAB0WIQQ+V5E9X2zL25Ai997jsR1kIkigkgUCZGHspQAKCRDjsR1kIkig
kh7JAQCjdmK4wB/LZmUJef7oqpacflOg4IrvViKsB86veDD82AD/b4E2BgmJYQmP
yvpWiOjPTxgs00uGp2bR6t+KmQ0zHds=
EOT;

        $publicKey = PublicKey::fromBytes(base64_decode(self::$dsaPublicKeyData));
        $packets = PacketList::decode(base64_decode($signatureData));
        $signature = $packets->offsetGet(0);
        $this->assertTrue($signature->verify($publicKey, self::LITERAL_TEXT));
    }

    public function testVerifyEcdsaP384Signature()
    {
        $signatureData = <<<EOT
iJUEARMJAB0WIQQFwIVJLRT5CXbnwrayAtni6tpEDAUCZGHzvAAKCRCyAtni6tpE
DDKOAX9/Yggxq+bAE6Tro3Rdph1ZdUCzQdhI9agQCzVQVHP1xpDhi5/LGj3VMm7N
OwO5mtYBfR6Ya1Vop1BgBeIdTAvcI9qnK7QoLQIjxqo7Q5ADrVcdJuS9fULx1Rff
cHReFWXuRg==
EOT;

        $publicKey = PublicKey::fromBytes(base64_decode(self::$ecdsaP384PublicKeyData));
        $packets = PacketList::decode(base64_decode($signatureData));
        $signature = $packets->offsetGet(0);
        $this->assertTrue($signature->verify($publicKey, self::LITERAL_TEXT));
    }

    public function testVerifyEcdsaBrainpoolSignature()
    {
        $signatureData = <<<EOT
iHUEARMIAB0WIQQG/uMIXUbcAHwOwvAcvNBD20TF1gUCZGH0YgAKCRAcvNBD20TF
1urbAP9vGfT9yD+yrbkRl7MyXW4ae1xKqz5qNwpbieiytm1jBwD/afBqcaU8maYj
fF5D7Ep6qI0Rxbe+CqxszbalXLLI6dI=
EOT;

        $publicKey = PublicKey::fromBytes(base64_decode(self::$ecdsaBrainpoolPublicKeyData));
        $packets = PacketList::decode(base64_decode($signatureData));
        $signature = $packets->offsetGet(0);
        $this->assertTrue($signature->verify($publicKey, self::LITERAL_TEXT));
    }

    public function testVerifyEddsaCurve25519Signature()
    {
        $signatureData = <<<EOT
iHUEARYKAB0WIQQcQRbrK1jPoZbFfdu9/xNRYMVqCwUCZGIDDAAKCRC9/xNRYMVq
C8JkAQDjt/kCR04bhHbxod+VtVYNrV7EwXDbZW8g9gLJt5CLygEAgAxrd61C1u2s
HOHMeoSApTEj6wNMvUvtie8VMStFDAI=
EOT;

        $publicKey = PublicKey::fromBytes(base64_decode(self::$eddsaCurve25519PublicKeyData));
        $packets = PacketList::decode(base64_decode($signatureData));
        $signature = $packets->offsetGet(0);
        $this->assertTrue($signature->verify($publicKey, self::LITERAL_TEXT));
    }
}
