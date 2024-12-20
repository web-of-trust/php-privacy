<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\{KeyAlgorithm, SymmetricAlgorithm};
use OpenPGP\Packet\PacketList;
use OpenPGP\Packet\PublicKeyEncryptedSessionKey;
use OpenPGP\Packet\SymEncryptedIntegrityProtectedData;
use OpenPGP\Packet\SecretSubkey;
use OpenPGP\Packet\Key\SessionKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * PKESKTest class for Public-Key Encrypted Session Key packet.
 */
class PKESKTest extends OpenPGPTestCase
{
    const PASSPHRASE = "password";
    const LITERAL_TEXT = "Hello, world!";

    private static $rsaSecretSubkey = <<<EOT
BGRUrD4BCACyRTYWSBsXFtxLOmSp3RvaW13GRh8HJ4p7adVqJpDBsvo8iInDgBt542/aoWDGIESA
MHBMlyq+QLfPuvPg187E0nsi1fh+P6sJ+gjNjSibyDdsBjHW6ZDksoB7lO5NhSCnzo63kMlP7QBH
hvOWaZSUHG3JqCsdElDSHkMrHpVzpyco+bTs7XK/E1iS0kC32yE7ShV/rltvl8hUKZF1npG3ytka
fegaEYESkM32/vygrCOWNC1Tea7kWe1A0+/ZYbgPh3blorNGICkUqiKfST9Xq26Lb67Kc38Gxjij
X9LAnOoxEyCjmCv/+ajNIDvMSQOtnTCapLpRrhLlzjvIDtOnABEBAAH+BwMCU66+g6RWISb/kIpn
DK3Sgc4XmiVF8NV0MS5rjxbZgBwrs61dCB2t2wV/evGZ1sUN1EOSleOG8z8J1lUZoz3DKzfUf5st
uVIm4c5P6U/0raU9JQpGid1kONDR3qeLDetCPcCEVsn7EXpxNccgRLkwUWCHm4ipwg+2mJlaTjsQ
v0GPnOxfV5coFoMZw1XkeroSzD/7Le9W5gx32FWbjSFpOZkRAbdqux+sD+u8jmGV84k42TZninew
JQz3XC7H9JljKPW5+dCenJBM56Vlef0fGq9SRXCpJoLGhdNh1JlFPt/3VAhzJYPAwzDz1ThpVRHF
Thq/9dMhMg2FJnOETIsty0i60rPeppbDauB67p+KVfqtX7u99gPYgpE/qRHPQN3IKo1G1bCrXBYJ
q1Ot8pzyJDZVf8qOk6I7ZmYVg27pZeReYgwnDkMpRJMn8w2/8sIKNAJ1BKX1pogNrWuLOpOioEx/
iZnn1BTqYTMneovgx758AkAvmcWh1i9qUygQlS9Jo/LHyoGAs06ywwQoqmf5dRCObOwW9fXEVnKw
lg1mVN65ZRyCql6FRcw+nicgijTwhRkVu4vfyTjKyLxEG6umRqVT7zDxoEd3KzA5JtFC2HUPcB7M
t75BqE0PoPSYfdKkWdqiCHbRHY+5Z6Wzv8jw2+lY+epd4IZEFe0r9AckCnjmPT1iln+RPCFWeuSS
HAL5kl+bvXSsfDmiqM9g7i36mtAe5zL9ZJ/A1Af4gOLq2YGVJTvDIr93V8es2XG0yngl5+/o8x8o
o630OHhhneEQ7blqGQKnBdrXtFKTVwGXA8EkCwgl4IK5OJrs9W+SkwBgfhxDCHprfFyH1ARSzjK1
TBGwJ0VVxJEtKxd0eQnmvNDYdo2kbGriXFcTyCzMGz/KKfqlsu3kPf/NCNgr+zxx8Z+xyDtG
EOT;

    private static $elGamalSecretSubkey = <<<EOT
BGRUrHEQCADgIyq1ibW3mAMoVMQQqO1ADO69uKPwlD4ANEh/2Wp0f2bY8kJKT01h/k1VtSEaFtpv
kXnyY7xIYW5mSCq8t1P3O0hEJhchzX2DCjHiT/2QL7piWG5Zs5unQ4jDh3I0Me1ciM2t5awmi/gn
5rEEwz9jpY2Rg6iZwaFJ0lrsCE8TpUyuctso7iKC8X6SOaF+/GJgn45aSOcrxBsFx2atGIGYAK9g
p3W0SINyJWy61NItTbi+35Y0Xms2NO6Qkq69lxQm3qEBHfcDovTbsmYOS4vLjAt/IB049d3jZjP1
c9jhzr74f0tulZBcDJEA7QpWcMRmQsddPOnp9JiPzoKwaRQnAAMFB/9Fvhljga21OLGO236/iK2l
vK+kP7wHrjN3Q8ifJnqpbdL4kmXM3KSwqmmtbeJX4HAhFFHJU3NrLGZeRElrUi7zXxlhcfodAlrO
rIldzs1n5/s2Vu8uto1q/+a6CwqN3Cix4mR95nofBf3rWQqot1oBm29UsBZLFW/qeK/WF85B+mNJ
cMP4TVIj3FY1Jgi5MsGnFWKxnl+TMwGO2xJz/63DtDKmEyCw4SMPbsF0ek6+RYFt2UBvQ/DXDjNy
pXQHGaN/KFh/UlbLKdBnaVaPy8I4HyzTqyjzvKmN5h8s1cv+7/SJKqWoqipdsp+PBYPdPVujT4Rt
ZSgDj7aW2N0nvDT5/gcDAs4nuOmbg4AW/52mifokiOaqZ9PXjv0J5asUJIfurNPn9JOPjLrwBpIq
3Lc5u6tOtzUTB8ynz2AE/17z1wotF/ENP8FryZQ84NJ4QiiYK0Joc95MXj+5uZYpNA==
EOT;
    private static $ecdhP384SecretSubkey = <<<EOT
BGRYd7USBSuBBAAiAwMEEWHAaBdPHihwch9e3b4VqOB89WeHI6fGWDLpKj6bJ/ME1VbDPhf0DN0N
c1s1wntRUFb9OjS06I8YQVBIPdyegmsMZj9J/fa0qFkd2r3siXb2x3zGqsxe1lvrYDVj9gDYAwEJ
Cf4HAwIcyJh6Un3tq/+P7HrG3HYoS3MBHwEHsYbsogsXCJyutYSZ3yn4Fuyk8FJnH9GGDJatBxkp
HjhNl+M7wpWyEyjh9WWJHFrC7Zgbx1RZbFHtM/aCtvqUQHqGwiR7uY9b0w==
EOT;
    private static $ecdhBrainpoolSecretSubkey = <<<EOT
BGRYXMESCSskAwMCCAEBBwIDBINvienMnFyJJCblEBJ2J9sBZ/hCAHGLbgDZPCC+mTLqDJJx47Sr
B3ZgWmrx1NRoT2pQfD2qqYo8jQJK8XlgyqIDAQgH/gcDApz0MLgF17Br/2e17kAJ360GEHYrfgn6
dstKPfglOcNKt8PdckwiF6g8gGm3WSPKU/7MkR2C+lKMOJWFxY0G9U77H35I+Vv9W9828ybAmxM=
EOT;
    private static $ecdhCurve25519SecretSubkey = <<<EOT
BGRYXQUSCisGAQQBl1UBBQEBB0BCbUFNqFZKpFLBB339cZrp7udovohvVMiG7qP9+ij6AQMBCAf+
BwMCXhynxjWHX9z//fP2s+xS5iJ1GuvkHqAq+i32Z7LO/92WrWb521yGgPfAipIfrwxwgLZByGjg
DE1hLVYK35eygNH+dtRvaK5/hLCNXKeUiQ==
EOT;

    public function testDecryptRSASessionKey()
    {
        $data = <<<EOT
hQEMA0vhs6Yh75BvAQf/d3sy2mx7mDExsPErVN7Dksswz0GErXcsWswsjI/GOFOA
DnEFyniJBGYJaL/kjv1fOqOlW0E4+9PZFxl7vg6bjjE7RiNgCIN5SMPp2G3w4KaT
a3emPFjRn9SanxTZCsrfGDHEdXxOjViersve2FRD7DniOpLLcZj3s5Q4MfD7UF6M
oWGnhynDYFETLS/D0j1ehm/2+0ZOr5xNxLLE0gLxYopg99is7kgE9ppAcbaJ7ixD
kKElBrxKOk3TdYJO0WbQ90UrNPt40fxFfSGXO3fdXE0ds4aRoUEzW3KRjamuMkux
danLSEjbCHUgDTj47/ly0/63N0/zzrgKIUES4LUzh9RIAQkCEFInanBKOrcss7wr
zRWdZZNnYoIwe96fREBcpXqxKvnIKm5/hjA4T2RMG5SnHKHCzkT9sEKSq/cLEQ6a
JnzOL3WiY9Ln
EOT;

        $packets = PacketList::decode(base64_decode($data));
        $secretSubkey = SecretSubkey::fromBytes(
            base64_decode(self::$rsaSecretSubkey)
        )->decrypt(self::PASSPHRASE);
        $pkesk = $packets->offsetGet(0);
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());
        $this->assertNull($pkesk->getSessionKey());

        $pkesk = $pkesk->decrypt($secretSubkey);
        $this->assertNotNull($pkesk->getSessionKey());
    }

    public function testEncryptRSASessionKey()
    {
        $sessionKey = SessionKey::produceKey();
        $secretSubkey = SecretSubkey::fromBytes(
            base64_decode(self::$rsaSecretSubkey)
        )->decrypt(self::PASSPHRASE);
        $pkesk = PublicKeyEncryptedSessionKey::encryptSessionKey(
            $secretSubkey->getPublicKey(),
            $sessionKey
        );
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());

        $packets = PacketList::decode($pkesk->encode());
        $pkesk = $packets->offsetGet(0)->decrypt($secretSubkey);
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());
        $this->assertEquals($sessionKey, $pkesk->getSessionKey());
    }

    public function testDecryptElGamalSessionKey()
    {
        $data = <<<EOT
hQIOA8BFPIqr53XbEAf/YZ0cFUri38dajZx25NbzEonD6FtRgpEW1ZZHcba+Uf47
E6SoBJlMFRunFvQv0X5DOtVKRCnvR3JLIrhbHnMCeCgIZgH7fYwHYPnWjDovwrA7
R5e1HFXXUtTClY62RPCkmJKtwwz/6Xt3vYzbZSIIV9qDywq9N1o7kIz/jvQheqBK
aHVBwF0XLDUv9y8nhOjDFq0OvFWO/RniYcxAv087hdoeeyg1PeqgoF3EsdBPtWJA
LyEbNt25Rpa3456+jCLQpqPYkD6RjBIUS3/ckdrU9kVnW3Oq95No0JRMPSFSY5Bc
r2V5ZynfvPjsHbRcaTmWkAwY2Bk7JdEpUIFnGUcnFQf/fTBYnmfa45W/8O0iAZaj
x5wfrMVwBjVg3dKvLmp5XXTUnESLhJp7dQyl2ixhKYKul2oIHiusCHgcoMNl2Xrw
b8zrmNHGKYUi8HKgwwjf+4vrbDXxCpwBW61rIKOc6LvmMcaEIZn3UBiN8XwgZWXs
CalhrbKOGI2m2kELEf8CMA1wLmu2X2x1PUEmbXsdWV2lb6Cg86g4ynq2KMr9q6wP
KtKcIyvWq3z7xVMZwfMYDgXkyAiAnSnHb29loChW3uUeByY7pQASFHAqQbPiqs1l
N6xQL6VOxYi6Lh6KIck7rnk+G7Ljsi2OmhlWYAFbJT4tVDcAigIz6Qbs1uinm5QU
GdRIAQkCELO1m6FiR2DqhiWA6AYeJ+v8locfcRzMvbx1fdgFXRkwoQQKuPGaM55H
qD3H8BKYxiMly2XHTqerSJlJoLD+R6h1PCa5
EOT;

        $packets = PacketList::decode(base64_decode($data));
        $secretSubkey = SecretSubkey::fromBytes(
            base64_decode(self::$elGamalSecretSubkey)
        )->decrypt(self::PASSPHRASE);
        $pkesk = $packets->offsetGet(0);
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());
        $this->assertNull($pkesk->getSessionKey());

        $pkesk = $pkesk->decrypt($secretSubkey);
        $this->assertNotNull($pkesk->getSessionKey());
    }

    public function testDecryptEcdhP384SessionKey()
    {
        $data = <<<EOT
hJ4DwLe5xr9YJLYSAwME4glkdCfl/lJ+fHi2XsEdZae24go9W+3HhXArjXKccP8t
ewKjfa/+r4SDUqLfhajcIKkNBHltCU90cA4Qi+wE/TSG3OuDl+CaBe+Zb7wBCyy4
arCVW5NsBLzcN5dnv7cAMDah/IT94ZXaIZCRcehx5/cJ1mb6vcAejaRKDwpXOd4f
1PDqjC1+0+39a7IBLXoOrdRIAQkCEPNehHxBgbpjzSMVwzr+y4Y4oyxGMdLmKFwa
O0t1Z6/Wb5jWV8dD1haVfk1oC4RfZDj76hSEbCyASB2++/JG+zArClgw
EOT;

        $packets = PacketList::decode(base64_decode($data));
        $secretSubkey = SecretSubkey::fromBytes(
            base64_decode(self::$ecdhP384SecretSubkey)
        )->decrypt(self::PASSPHRASE);
        $pkesk = $packets->offsetGet(0);
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());
        $this->assertNull($pkesk->getSessionKey());

        $pkesk = $pkesk->decrypt($secretSubkey);
        $this->assertNotNull($pkesk->getSessionKey());
    }

    public function testEncryptEcdhP384SessionKey()
    {
        $sessionKey = SessionKey::produceKey();
        $secretSubkey = SecretSubkey::fromBytes(
            base64_decode(self::$ecdhP384SecretSubkey)
        )->decrypt(self::PASSPHRASE);
        $pkesk = PublicKeyEncryptedSessionKey::encryptSessionKey(
            $secretSubkey->getPublicKey(),
            $sessionKey
        );
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());

        $packets = PacketList::decode($pkesk->encode());
        $pkesk = $packets->offsetGet(0)->decrypt($secretSubkey);
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());
        $this->assertEquals($sessionKey, $pkesk->getSessionKey());
    }

    public function testDecryptEcdhBrainpoolSessionKey()
    {
        $data = <<<EOT
hH4DCKVb2x1nPV0SAgMEXc56LqYoYJmNo0hSbjHJqqnsjjJCcQJUr7RCyIew8y1B
uonkedTN08+6B6z1DcuHXr1CtWmo8O1RfA1bIAWpijCapYOMczR8UvO2BUixisIx
lyfm0MBhx1pLnNVKCuvgAu2t9DDoTo2E8HpeHfLNC1DUSAEJAhCosmYmOp+c0Jy/
a/vBHQm/YVjRG3ixReDpp5R5PpBQJJei/xwMS733bwLriGSWBkdLcEKk49Ec9btE
NeGzlkMV4z0dRA==
EOT;

        $packets = PacketList::decode(base64_decode($data));
        $secretSubkey = SecretSubkey::fromBytes(
            base64_decode(self::$ecdhBrainpoolSecretSubkey)
        )->decrypt(self::PASSPHRASE);
        $pkesk = $packets->offsetGet(0);
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());
        $this->assertNull($pkesk->getSessionKey());

        $pkesk = $pkesk->decrypt($secretSubkey);
        $this->assertNotNull($pkesk->getSessionKey());
    }

    public function testEncryptEcdhBrainpoolSessionKey()
    {
        $sessionKey = SessionKey::produceKey();
        $secretSubkey = SecretSubkey::fromBytes(
            base64_decode(self::$ecdhBrainpoolSecretSubkey)
        )->decrypt(self::PASSPHRASE);
        $pkesk = PublicKeyEncryptedSessionKey::encryptSessionKey(
            $secretSubkey->getPublicKey(),
            $sessionKey
        );
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());

        $packets = PacketList::decode($pkesk->encode());
        $pkesk = $packets->offsetGet(0)->decrypt($secretSubkey);
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());
        $this->assertEquals($sessionKey, $pkesk->getSessionKey());
    }

    public function testDecryptEcdhCurve25519SessionKey()
    {
        $data = <<<EOT
hF4DBE6sk/C2nqASAQdAXZXMsrK2k5aAeJ0gl+RI4xIW6yCzM95FWxk4p/NGRiIw
KPENvQMA3yieBRk2otUFUf2ryA3IcgeiAzwiFB16tlgTy1HMJ8k+/fr9esnXHkRr
1EgBCQIQE1IPf72JCyfRVzSTyCZ8pHutG2zjRmzxCReF23S+7IlQ1asCq2Zjn9I2
AYd6zKgVJVb+5kvc/i034xNKjDl9IXOd7AE=
EOT;

        $packets = PacketList::decode(base64_decode($data));
        $secretSubkey = SecretSubkey::fromBytes(
            base64_decode(self::$ecdhCurve25519SecretSubkey)
        )->decrypt(self::PASSPHRASE);
        $pkesk = $packets->offsetGet(0);
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());
        $this->assertNull($pkesk->getSessionKey());

        $pkesk = $pkesk->decrypt($secretSubkey);
        $this->assertNotNull($pkesk->getSessionKey());
    }

    public function testEncryptEcdhCurve25519SessionKey()
    {
        $sessionKey = SessionKey::produceKey();
        $secretSubkey = SecretSubkey::fromBytes(
            base64_decode(self::$ecdhCurve25519SecretSubkey)
        )->decrypt(self::PASSPHRASE);
        $pkesk = PublicKeyEncryptedSessionKey::encryptSessionKey(
            $secretSubkey->getPublicKey(),
            $sessionKey
        );
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());

        $packets = PacketList::decode($pkesk->encode());
        $pkesk = $packets->offsetGet(0)->decrypt($secretSubkey);
        $this->assertSame($secretSubkey->getKeyID(), $pkesk->getKeyID());
        $this->assertEquals($sessionKey, $pkesk->getSessionKey());
    }

    public function testX25519AeadOcbDecryption()
    {
        $subkeyData =
            "BmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24EL4=";
        $subkey = SecretSubkey::fromBytes(base64_decode($subkeyData));

        $pkeskData =
            "BiEGEsg/HnBvYwj+FRpBd0Oh8DN5DpPpl4SI0ds3jamTCIUZh88Y1fG1P4F8zloATPOTzIlYvdwGXyX4SvUJsX3TZ2QY3qNVQ3lWYXkB4GlX+8qKakeltRU+jTq3";
        $pkesk = PublicKeyEncryptedSessionKey::fromBytes(
            base64_decode($pkeskData)
        )->decrypt($subkey);

        $sessionKey = $pkesk->getSessionKey();
        $this->assertSame(
            "dd708f6fa1ed65114d68d2343e7c2f1d",
            bin2hex($sessionKey->getEncryptionKey())
        );

        $seipdData =
            "AgcCBmFkFlNb4LBxbWDgUqVsTEB/nrNrDvr+mtCg35sDPGmiG6nr0sDslb9WnSXJme5KPeFwWPQN+otMaCvj+7vXsn6w9Zu1AF+Ax8b0A4jDCtQGqwUT3Nb5/XN2VihuEXfQD4iK2zHE";
        $seipd = SymEncryptedIntegrityProtectedData::fromBytes(
            base64_decode($seipdData)
        );
        $seipd = $seipd->decryptWithSessionKey($sessionKey);
        $literalData = $seipd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    }

    public function testX25519Encryption()
    {
        $sessionKey = SessionKey::produceKey(SymmetricAlgorithm::Aes256);
        $secretSubkey = SecretSubkey::generate(KeyAlgorithm::X25519);
        $pkesk = PublicKeyEncryptedSessionKey::encryptSessionKey(
            $secretSubkey->getPublicKey(),
            $sessionKey
        );
        $this->assertSame(
            $secretSubkey->getFingerprint(),
            $pkesk->getKeyFingerprint()
        );

        $packets = PacketList::decode($pkesk->encode());
        $pkesk = $packets->offsetGet(0)->decrypt($secretSubkey);
        $this->assertSame(
            $secretSubkey->getFingerprint(),
            $pkesk->getKeyFingerprint()
        );
        $this->assertEquals(
            $sessionKey->getEncryptionKey(),
            $pkesk->getSessionKey()->getEncryptionKey()
        );
    }

    public function testX448Encryption()
    {
        $sessionKey = SessionKey::produceKey(SymmetricAlgorithm::Aes256);
        $secretSubkey = SecretSubkey::generate(KeyAlgorithm::X448);
        $pkesk = PublicKeyEncryptedSessionKey::encryptSessionKey(
            $secretSubkey->getPublicKey(),
            $sessionKey
        );
        $this->assertSame(
            $secretSubkey->getFingerprint(),
            $pkesk->getKeyFingerprint()
        );

        $packets = PacketList::decode($pkesk->encode());
        $pkesk = $packets->offsetGet(0)->decrypt($secretSubkey);
        $this->assertSame(
            $secretSubkey->getFingerprint(),
            $pkesk->getKeyFingerprint()
        );
        $this->assertEquals(
            $sessionKey->getEncryptionKey(),
            $pkesk->getSessionKey()->getEncryptionKey()
        );
    }
}
