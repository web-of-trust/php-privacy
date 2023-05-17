<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use phpseclib3\Crypt\Random;
use OpenPGP\Enum\KeyFlag;
use OpenPGP\Enum\SignatureType;
use OpenPGP\Enum\SignatureSubpacketType;
use OpenPGP\Enum\SupportFeature;
use OpenPGP\Packet\PacketList;
use OpenPGP\Packet\PublicKey;
use OpenPGP\Packet\SecretKey;
use OpenPGP\Packet\Signature;
use OpenPGP\Packet\SignatureSubpacket;
use OpenPGP\Packet\Signature\Features;
use OpenPGP\Packet\Signature\KeyFlags;
use OpenPGP\Packet\SubpacketReader;
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

    private static $rsaSecretKeyData = <<<EOT
BGRUrD4BCACe8iv48dGvqnbOuPv1DnnrasH/NZ5bbpGHW0gSOXb4p2d7VcfA6hfoyq1yEuZ2VDzJ
WpkhVnKMF1Ytj7d8mtnGsTQ6NfGrV9jRhGIxAYIgiDjzuhIejzMrTR/RAh9aARPTuEayRXoShTEg
cQfZxIQKwwU5hE4PDZFhq0h/T83eImWidUZwt3zw6jWq29nDtmtR96x+xznG0utZrHsbkxNtuLpX
YlrMl9Lcz9vbntpK45aq35P3cfg5UEjCLj1TAq6LPFnfiwbQcNkbsTRsxPqWpX4J6v5ZabJIFGyd
K14eiohYTbp7Uvr/e3yRhTirWYz4KnJwuFOsemuSjSAGi3C5ABEBAAH+BwMCLQGcMzPKel7/nlml
LznQdMJ5SimdfqT4NvlNkb5QN+IqXfqOg01EF0cbWsT510j8iAox1auK9lJstyeqKK1ttqdF/2wf
dymZ0UQn+BqqvYqACMQmBhXvi/jr4m+4AJC3PLwIapLZaQS/HT+sqqU2WheSCUD2v4pA069B0jGL
nQ8t+j1dJrentK/hr6S/q06G/gOehcRKPYnTjM2lDv8TUA7Yg45dYwRKRg3IneQor2Yh2d0tvL78
U4Dq1YMFfgvsO4szknklq4sQGKLH4DRv+Cv+sALZOFTNv0h851tLP+22RnwfKUbQ9F9uw0MG9Rav
7Wy+ililDQXcU1kYMMIU8vBbGmwjwRrP7QM1NbmGrOEpdDZKgAUWnyv+EtMPxfytbFcj8rF2yAf5
xd3lrQdQcR8ePxE8dbbV/c1KwkbKDfXAQOSoEFJpFNqXEAK9he59oKICH+4yMqXxIXYDaMognhtP
hH/tZCgYRzLavt9dR6BJ9VGhgzNgtWsvn+5L4oBfDBF2XjB3mKLMdjvO9wH1SLLRaAtIx2xGdT1c
ediMVFo5uNdDC97CQwAx4QDlX5RbQHe7lq0T7t2WQ8LagjciTeDOtKEf5WN69a1kGSzgJn6rm1GL
fCc93clNyiYygS+GaVFnhr/hEdq8pRiIUs7FlpK9lPNMv9Ecs03fGE0ZzA3gWyb1KZLpwFLXk2XR
BM8cDkFsIy9Mn9e9p85IcXZ3WDuJms/gkYRb1CsVTsvVSft1+xYi/Ve6JmIeRkE1weRLuOMkqvFJ
QdjujszGY2uSv1iTik/46DAEf0yJ7/7Fwt9gSgTLEbh0NIGE21Z11BKY+ovITfgrmJOhP9kQ6oIX
RfZglUaCOkOPtqPMQNOpZiV3VY6IOay+r7y9Rx2xT03WrnSowNZQXSCksonthXUZAXoGSeFO
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

private static $dsaSecretKeyData = <<<EOT
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
2R6iMnzQc3iIUX0Ns/vE3P4HAwI031TJbUMz3P8bS2hgTRNhrQbqMISMVyoDSrYH9uYvEfxeAEBV
KtquoXIM7ith6WK8iUzZ9jyXcWv+iFDE8cDpLEGvR7x3NEt0SfCtN0SL
EOT;

    private static $ecdsaP384PublicKeyData = <<<EOT
BGRYd7UTBSuBBAAiAwME3Z/lmJrDGnYHvT7xe5ei8xFfsCsrH+6AjmSftcJEYCCTy4CupXlvp5wb
FLQ2klduC2c09LzjULVFn4uQKdMacYb7X0UjI2q6MLGP1fpmg7mq4F8myVJx6lkvpHK44xDh
EOT;

    private static $ecdsaP384SecretKeyData = <<<EOT
BGRYd7UTBSuBBAAiAwME3Z/lmJrDGnYHvT7xe5ei8xFfsCsrH+6AjmSftcJEYCCTy4CupXlvp5wb
FLQ2klduC2c09LzjULVFn4uQKdMacYb7X0UjI2q6MLGP1fpmg7mq4F8myVJx6lkvpHK44xDh/gcD
AjbYiI4QU+mo/woxqTXpIZE1wzaaNJ5+iRA7vvc6rdJZSjQUkXTJ3/zOyI4970a4UDTJ948+jiUt
aJrhbMr17UySI58IyBvTxA3hFy63JRJWy5dhJU7kQ3PljGTlqOGB
EOT;

    private static $ecdsaBrainpoolPublicKeyData = <<<EOT
BGRYXMETCSskAwMCCAEBBwIDBHKh5xdXoTfino6vulZBw4fl5lMtKgzXIeG9zhJuBInpE7gOlxes
07/JY2b9aIUph0fAku1xE+ljP5I/5pI5qrQ=
EOT;

    private static $ecdsaBrainpoolSecretKeyData = <<<EOT
BGRYXMETCSskAwMCCAEBBwIDBHKh5xdXoTfino6vulZBw4fl5lMtKgzXIeG9zhJuBInpE7gOlxes
07/JY2b9aIUph0fAku1xE+ljP5I/5pI5qrT+BwMCfKl8O5GIbj3/eruMvK1KnzWCGiQutGTYgQmP
u5aHJEwxtiXZFAHUTxoHgr3yd0IewonQL4Xxz25Zmp1iNL2VSyfPE5v8EDwgWcxCT9m1pQ==
EOT;

    private static $eddsaCurve25519PublicKeyData = <<<EOT
BGRYXQUWCSsGAQQB2kcPAQEHQLvR0VoiVSt3+xzxSSQrR7/yrMzQG8OXueMhIkQb0UPM
EOT;

    private static $eddsaCurve25519SecretKeyData = <<<EOT
BGRYXQUWCSsGAQQB2kcPAQEHQLvR0VoiVSt3+xzxSSQrR7/yrMzQG8OXueMhIkQb0UPM/gcDAg3L
LOtx/PSU/9E+PgO1Rd79U+hHRifxAcg+kLq3aoLBbA7RmrVdDTeQvoFl3C+WCC1WleUW21FsUpce
31nuheiWbgVEXVXQUOcXaVbGVGY=
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

    public function testRsaSigning()
    {
        $message = Random::string(100);
        $secretKey = SecretKey::fromBytes(base64_decode(self::$rsaSecretKeyData))->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromBytes(base64_decode(self::$rsaPublicKeyData));

        $signature = Signature::createSignature(
            $secretKey,
            SignatureType::Standalone,
            $message
        );
        $this->assertTrue($signature->verify($publicKey, $message));
        $this->assertFalse($signature->verify($publicKey, self::LITERAL_TEXT));
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

    public function testDsaSigning()
    {
        $message = Random::string(100);
        $secretKey = SecretKey::fromBytes(base64_decode(self::$dsaSecretKeyData))->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromBytes(base64_decode(self::$dsaPublicKeyData));

        $signature = Signature::createSignature(
            $secretKey,
            SignatureType::Standalone,
            $message
        );
        $this->assertTrue($signature->verify($publicKey, $message));
        $this->assertFalse($signature->verify($publicKey, self::LITERAL_TEXT));
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

    public function testEcdsaP384Signing()
    {
        $message = Random::string(100);
        $secretKey = SecretKey::fromBytes(base64_decode(self::$ecdsaP384SecretKeyData))->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromBytes(base64_decode(self::$ecdsaP384PublicKeyData));

        $signature = Signature::createSignature(
            $secretKey,
            SignatureType::Standalone,
            $message
        );
        $this->assertTrue($signature->verify($publicKey, $message));
        $this->assertFalse($signature->verify($publicKey, self::LITERAL_TEXT));
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

    public function testEcdsaBrainpoolSigning()
    {
        $message = Random::string(100);
        $secretKey = SecretKey::fromBytes(base64_decode(self::$ecdsaBrainpoolSecretKeyData))->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromBytes(base64_decode(self::$ecdsaBrainpoolPublicKeyData));

        $signature = Signature::createSignature(
            $secretKey,
            SignatureType::Standalone,
            $message
        );
        $this->assertTrue($signature->verify($publicKey, $message));
        $this->assertFalse($signature->verify($publicKey, self::LITERAL_TEXT));
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

    public function testEddsaCurve25519Signing()
    {
        $message = Random::string(100);
        $secretKey = SecretKey::fromBytes(base64_decode(self::$eddsaCurve25519SecretKeyData))->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromBytes(base64_decode(self::$eddsaCurve25519PublicKeyData));

        $signature = Signature::createSignature(
            $secretKey,
            SignatureType::Standalone,
            $message
        );
        $this->assertTrue($signature->verify($publicKey, $message));
        $this->assertFalse($signature->verify($publicKey, self::LITERAL_TEXT));
    }

    public function testFeatures()
    {
        $features = Features::fromFeatures(
            SupportFeature::ModificationDetection->value |
            SupportFeature::AeadEncryptedData->value |
            SupportFeature::Version5PublicKey->value
        );
        $this->assertTrue($features->supprtModificationDetection());
        $this->assertTrue($features->supportAeadEncryptedData());
        $this->assertTrue($features->supportVersion5PublicKey());
    }

    public function testKeyFlag()
    {
        $keyFlags = KeyFlags::fromFlags(
            KeyFlag::CertifyKeys->value |
            KeyFlag::SignData->value |
            KeyFlag::EncryptCommunication->value |
            KeyFlag::EncryptStorage->value |
            KeyFlag::SplitPrivateKey->value |
            KeyFlag::Authentication->value |
            KeyFlag::SharedPrivateKey->value
        );
        foreach (KeyFlag::cases() as $flag) {
            $this->assertSame($keyFlags->getFlags() & $flag->value, $flag->value);
        }
        $this->assertTrue($keyFlags->isCertifyKeys());
        $this->assertTrue($keyFlags->isSignData());
        $this->assertTrue($keyFlags->isEncryptCommunication());
        $this->assertTrue($keyFlags->isEncryptStorage());
    }

    public function testSignatureSubpackets()
    {
        $initSubpackets = array_map(
            static fn ($type) => new SignatureSubpacket($type->value, Random::string(100)),
            SignatureSubpacketType::cases()
        );
        $subpackets = SubpacketReader::readSignatureSubpackets(implode(
            array_map(static fn ($subpacket) => $subpacket->toBytes(), $initSubpackets)
        ));
        $this->assertSame(count($initSubpackets), count($subpackets));
        foreach ($subpackets as $key => $subpacket) {
            $initSubpacket = $initSubpackets[$key];
            $this->assertSame($initSubpacket->getType(), $subpacket->getType());
            $this->assertSame($initSubpacket->getData(), $subpacket->getData());
        }
    }
}
