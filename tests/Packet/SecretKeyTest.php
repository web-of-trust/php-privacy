<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Common\Config;
use OpenPGP\Enum\{
    CurveOid,
    KeyAlgorithm,
    DHKeySize,
    RSAKeySize,
};
use OpenPGP\Packet\SecretKey;
use OpenPGP\Packet\SecretSubkey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for secret key packet.
 */
class SecretKeyTest extends OpenPGPTestCase
{
    const PASSPHRASE = 'password'; 

    public function testRsaSecretKey()
    {
        $data = <<<EOT
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
        $secretKey = SecretKey::fromBytes(base64_decode($data))->decrypt(self::PASSPHRASE);
        $this->assertSame('fc5004df9473277107eaa605184d0dc4f5c532b2', bin2hex($secretKey->getFingerprint()));
        $this->assertSame('184d0dc4f5c532b2', bin2hex($secretKey->getKeyID()));
        $this->assertSame(4, $secretKey->getVersion());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
    }

    public function testRsaSecretSubkey()
    {
        $data = <<<EOT
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
        $secretSubkey = SecretSubkey::fromBytes(base64_decode($data))->decrypt(self::PASSPHRASE);
        $this->assertSame('42badbbe0f2acabacd6cac7c4be1b3a621ef906f', bin2hex($secretSubkey->getFingerprint()));
        $this->assertSame('4be1b3a621ef906f', bin2hex($secretSubkey->getKeyID()));
        $this->assertSame(4, $secretSubkey->getVersion());
        $this->assertTrue($secretSubkey->getKeyMaterial()->isValid());
    }

    public function testDsaSecretKey()
    {
        $data = <<<EOT
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
        $secretKey = SecretKey::fromBytes(base64_decode($data))->decrypt(self::PASSPHRASE);
        $this->assertSame('3e57913d5f6ccbdb9022f7dee3b11d642248a092', bin2hex($secretKey->getFingerprint()));
        $this->assertSame('e3b11d642248a092', bin2hex($secretKey->getKeyID()));
        $this->assertSame(4, $secretKey->getVersion());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
    }

    public function testElGamalSecretSubkey()
    {
        $data = <<<EOT
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
        $secretSubkey = SecretSubkey::fromBytes(base64_decode($data))->decrypt(self::PASSPHRASE);
        $this->assertSame('420a452a98ea130c7747e0b2c0453c8aabe775db', bin2hex($secretSubkey->getFingerprint()));
        $this->assertSame('c0453c8aabe775db', bin2hex($secretSubkey->getKeyID()));
        $this->assertSame(4, $secretSubkey->getVersion());
        $this->assertTrue($secretSubkey->getKeyMaterial()->isValid());
    }

    public function testEcdsaP384SecretKey()
    {
        $data = <<<EOT
BGRYd7UTBSuBBAAiAwME3Z/lmJrDGnYHvT7xe5ei8xFfsCsrH+6AjmSftcJEYCCTy4CupXlvp5wb
FLQ2klduC2c09LzjULVFn4uQKdMacYb7X0UjI2q6MLGP1fpmg7mq4F8myVJx6lkvpHK44xDh/gcD
AjbYiI4QU+mo/woxqTXpIZE1wzaaNJ5+iRA7vvc6rdJZSjQUkXTJ3/zOyI4970a4UDTJ948+jiUt
aJrhbMr17UySI58IyBvTxA3hFy63JRJWy5dhJU7kQ3PljGTlqOGB
EOT;
        $secretKey = SecretKey::fromBytes(base64_decode($data))->decrypt(self::PASSPHRASE);
        $this->assertSame('05c085492d14f90976e7c2b6b202d9e2eada440c', bin2hex($secretKey->getFingerprint()));
        $this->assertSame('b202d9e2eada440c', bin2hex($secretKey->getKeyID()));
        $this->assertSame(4, $secretKey->getVersion());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
    }

    public function testEcdhP384SecretSubkey()
    {
        $data = <<<EOT
BGRYd7USBSuBBAAiAwMEEWHAaBdPHihwch9e3b4VqOB89WeHI6fGWDLpKj6bJ/ME1VbDPhf0DN0N
c1s1wntRUFb9OjS06I8YQVBIPdyegmsMZj9J/fa0qFkd2r3siXb2x3zGqsxe1lvrYDVj9gDYAwEJ
Cf4HAwIcyJh6Un3tq/+P7HrG3HYoS3MBHwEHsYbsogsXCJyutYSZ3yn4Fuyk8FJnH9GGDJatBxkp
HjhNl+M7wpWyEyjh9WWJHFrC7Zgbx1RZbFHtM/aCtvqUQHqGwiR7uY9b0w==
EOT;
        $secretSubkey = SecretSubkey::fromBytes(base64_decode($data))->decrypt(self::PASSPHRASE);
        $this->assertSame('7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6', bin2hex($secretSubkey->getFingerprint()));
        $this->assertSame('c0b7b9c6bf5824b6', bin2hex($secretSubkey->getKeyID()));
        $this->assertSame(4, $secretSubkey->getVersion());
        $this->assertTrue($secretSubkey->getKeyMaterial()->isValid());
    }

    public function testEcdsaBrainpoolP256SecretKey()
    {
        $data = <<<EOT
BGRYXMETCSskAwMCCAEBBwIDBHKh5xdXoTfino6vulZBw4fl5lMtKgzXIeG9zhJuBInpE7gOlxes
07/JY2b9aIUph0fAku1xE+ljP5I/5pI5qrT+BwMCfKl8O5GIbj3/eruMvK1KnzWCGiQutGTYgQmP
u5aHJEwxtiXZFAHUTxoHgr3yd0IewonQL4Xxz25Zmp1iNL2VSyfPE5v8EDwgWcxCT9m1pQ==
EOT;
        $secretKey = SecretKey::fromBytes(base64_decode($data))->decrypt(self::PASSPHRASE);
        $this->assertSame('06fee3085d46dc007c0ec2f01cbcd043db44c5d6', bin2hex($secretKey->getFingerprint()));
        $this->assertSame('1cbcd043db44c5d6', bin2hex($secretKey->getKeyID()));
        $this->assertSame(4, $secretKey->getVersion());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
    }

    public function testEcdhPrainpoolP256SecretSubkey()
    {
        $data = <<<EOT
BGRYXMESCSskAwMCCAEBBwIDBINvienMnFyJJCblEBJ2J9sBZ/hCAHGLbgDZPCC+mTLqDJJx47Sr
B3ZgWmrx1NRoT2pQfD2qqYo8jQJK8XlgyqIDAQgH/gcDApz0MLgF17Br/2e17kAJ360GEHYrfgn6
dstKPfglOcNKt8PdckwiF6g8gGm3WSPKU/7MkR2C+lKMOJWFxY0G9U77H35I+Vv9W9828ybAmxM=
EOT;
        $secretSubkey = SecretSubkey::fromBytes(base64_decode($data))->decrypt(self::PASSPHRASE);
        $this->assertSame('457b5979545fba09be179db808a55bdb1d673d5d', bin2hex($secretSubkey->getFingerprint()));
        $this->assertSame('08a55bdb1d673d5d', bin2hex($secretSubkey->getKeyID()));
        $this->assertSame(4, $secretSubkey->getVersion());
        $this->assertTrue($secretSubkey->getKeyMaterial()->isValid());
    }

    public function testEddsaCurve25519SecretKey()
    {
        $data = <<<EOT
BGRYXQUWCSsGAQQB2kcPAQEHQLvR0VoiVSt3+xzxSSQrR7/yrMzQG8OXueMhIkQb0UPM/gcDAg3L
LOtx/PSU/9E+PgO1Rd79U+hHRifxAcg+kLq3aoLBbA7RmrVdDTeQvoFl3C+WCC1WleUW21FsUpce
31nuheiWbgVEXVXQUOcXaVbGVGY=
EOT;
        $secretKey = SecretKey::fromBytes(base64_decode($data))->decrypt(self::PASSPHRASE);
        $this->assertSame('1c4116eb2b58cfa196c57ddbbdff135160c56a0b', bin2hex($secretKey->getFingerprint()));
        $this->assertSame('bdff135160c56a0b', bin2hex($secretKey->getKeyID()));
        $this->assertSame(4, $secretKey->getVersion());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
    }

    public function testEcdhCurve25519SecretSubkey()
    {
        $data = <<<EOT
BGRYXQUSCisGAQQBl1UBBQEBB0BCbUFNqFZKpFLBB339cZrp7udovohvVMiG7qP9+ij6AQMBCAf+
BwMCXhynxjWHX9z//fP2s+xS5iJ1GuvkHqAq+i32Z7LO/92WrWb521yGgPfAipIfrwxwgLZByGjg
DE1hLVYK35eygNH+dtRvaK5/hLCNXKeUiQ==
EOT;
        $secretSubkey = SecretSubkey::fromBytes(base64_decode($data))->decrypt(self::PASSPHRASE);
        $this->assertSame('8efa53a375fc569aa9ca564a044eac93f0b69ea0', bin2hex($secretSubkey->getFingerprint()));
        $this->assertSame('044eac93f0b69ea0', bin2hex($secretSubkey->getKeyID()));
        $this->assertSame(4, $secretSubkey->getVersion());
        $this->assertTrue($secretSubkey->getKeyMaterial()->isValid());
    }

    public function testGenerateRSASecretKey()
    {
        $secretKey = SecretKey::generate(KeyAlgorithm::RsaEncryptSign);
        $this->assertFalse($secretKey->isEncrypted());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
        $this->assertSame(2048, $secretKey->getKeyStrength());
        $this->assertSame(4, $secretKey->getVersion());

        $encryptedSecretKey = $secretKey->encrypt(self::PASSPHRASE);
        $this->assertTrue($encryptedSecretKey->isEncrypted());

        $decryptedSecretKey = SecretKey::fromBytes($encryptedSecretKey->toBytes())->decrypt(self::PASSPHRASE);
        $this->assertSame($secretKey->getFingerprint(), $decryptedSecretKey->getFingerprint());
        $this->assertEquals(
            $secretKey->getKeyMaterial()->getPrivateKey()->toString('Raw'),
            $decryptedSecretKey->getKeyMaterial()->getPrivateKey()->toString('Raw')
        );
    }

    public function testGenerateDSASecretKey()
    {
        $secretKey = SecretKey::generate(KeyAlgorithm::Dsa);
        $this->assertFalse($secretKey->isEncrypted());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
        $this->assertSame(2048, $secretKey->getKeyStrength());
        $this->assertSame(4, $secretKey->getVersion());

        $encryptedSecretKey = $secretKey->encrypt(self::PASSPHRASE);
        $this->assertTrue($encryptedSecretKey->isEncrypted());

        $decryptedSecretKey = SecretKey::fromBytes($encryptedSecretKey->toBytes())->decrypt(self::PASSPHRASE);
        $this->assertSame($secretKey->getFingerprint(), $decryptedSecretKey->getFingerprint());
        $this->assertEquals(
            $secretKey->getKeyMaterial()->getPrivateKey()->toString('Raw'),
            $decryptedSecretKey->getKeyMaterial()->getPrivateKey()->toString('Raw')
        );
    }

    public function testGenerateElGamalSecretKey()
    {
        $secretKey = SecretKey::generate(KeyAlgorithm::ElGamal);
        $this->assertFalse($secretKey->isEncrypted());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
        $this->assertSame(2048, $secretKey->getKeyStrength());
        $this->assertSame(4, $secretKey->getVersion());

        $encryptedSecretKey = $secretKey->encrypt(self::PASSPHRASE);
        $this->assertTrue($encryptedSecretKey->isEncrypted());

        $decryptedSecretKey = SecretKey::fromBytes($encryptedSecretKey->toBytes())->decrypt(self::PASSPHRASE);
        $this->assertSame($encryptedSecretKey->getFingerprint(), $decryptedSecretKey->getFingerprint());
        $this->assertEquals(
            $secretKey->getKeyMaterial(),
            $decryptedSecretKey->getKeyMaterial()
        );
    }

    public function testGenerateEcDsaSecretKeySecp521r1()
    {
        $secretKey = SecretKey::generate(
            KeyAlgorithm::EcDsa,
            curveOid: CurveOid::Secp521r1
        );
        $this->assertFalse($secretKey->isEncrypted());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
        $this->assertSame(521, $secretKey->getKeyStrength());
        $this->assertSame(4, $secretKey->getVersion());

        $encryptedSecretKey = $secretKey->encrypt(self::PASSPHRASE);
        $this->assertTrue($encryptedSecretKey->isEncrypted());

        $decryptedSecretKey = SecretKey::fromBytes($encryptedSecretKey->toBytes())->decrypt(self::PASSPHRASE);
        $this->assertSame($encryptedSecretKey->getFingerprint(), $decryptedSecretKey->getFingerprint());
        $this->assertSame(
            $secretKey->getKeyMaterial()->getPrivateKey()->toString('PKCS8'),
            $decryptedSecretKey->getKeyMaterial()->getPrivateKey()->toString('PKCS8')
        );
    }

    public function testGenerateEcDsaSecretKeyBrainpoolP512r1()
    {
        $secretKey = SecretKey::generate(
            KeyAlgorithm::EcDsa,
            curveOid: CurveOid::BrainpoolP512r1
        );
        $this->assertFalse($secretKey->isEncrypted());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
        $this->assertSame(512, $secretKey->getKeyStrength());
        $this->assertSame(4, $secretKey->getVersion());

        $encryptedSecretKey = $secretKey->encrypt(self::PASSPHRASE);
        $this->assertTrue($encryptedSecretKey->isEncrypted());

        $decryptedSecretKey = SecretKey::fromBytes($encryptedSecretKey->toBytes())->decrypt(self::PASSPHRASE);
        $this->assertSame($encryptedSecretKey->getFingerprint(), $decryptedSecretKey->getFingerprint());
        $this->assertSame(
            $secretKey->getKeyMaterial()->getPrivateKey()->toString('PKCS8'),
            $decryptedSecretKey->getKeyMaterial()->getPrivateKey()->toString('PKCS8')
        );
    }

    public function testGenerateEdDsaSecretKeyEd25519()
    {
        $secretKey = SecretKey::generate(
            KeyAlgorithm::EdDsa,
            curveOid: CurveOid::Ed25519
        );
        $this->assertFalse($secretKey->isEncrypted());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
        $this->assertSame(255, $secretKey->getKeyStrength());
        $this->assertSame(4, $secretKey->getVersion());

        $encryptedSecretKey = $secretKey->encrypt(self::PASSPHRASE);
        $this->assertTrue($encryptedSecretKey->isEncrypted());

        $decryptedSecretKey = SecretKey::fromBytes($encryptedSecretKey->toBytes())->decrypt(self::PASSPHRASE);
        $this->assertSame($encryptedSecretKey->getFingerprint(), $decryptedSecretKey->getFingerprint());
        $this->assertSame(
            $secretKey->getKeyMaterial()->getPrivateKey()->toString('PKCS8'),
            $decryptedSecretKey->getKeyMaterial()->getPrivateKey()->toString('PKCS8')
        );
    }

    public function testGenerateEcdhSecretKeySecp521r1()
    {
        $secretKey = SecretKey::generate(
            KeyAlgorithm::Ecdh,
            curveOid: CurveOid::Secp521r1
        );
        $this->assertFalse($secretKey->isEncrypted());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
        $this->assertSame(521, $secretKey->getKeyStrength());
        $this->assertSame(4, $secretKey->getVersion());

        $encryptedSecretKey = $secretKey->encrypt(self::PASSPHRASE);
        $this->assertTrue($encryptedSecretKey->isEncrypted());

        $decryptedSecretKey = SecretKey::fromBytes($encryptedSecretKey->toBytes())->decrypt(self::PASSPHRASE);
        $this->assertSame($encryptedSecretKey->getFingerprint(), $decryptedSecretKey->getFingerprint());
        $this->assertSame(
            $secretKey->getKeyMaterial()->getPrivateKey()->toString('PKCS8'),
            $decryptedSecretKey->getKeyMaterial()->getPrivateKey()->toString('PKCS8')
        );
    }

    public function testGenerateEcdhSecretKeyBrainpoolP512r1()
    {
        $secretKey = SecretKey::generate(
            KeyAlgorithm::Ecdh,
            curveOid: CurveOid::BrainpoolP512r1
        );
        $this->assertFalse($secretKey->isEncrypted());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
        $this->assertSame(512, $secretKey->getKeyStrength());
        $this->assertSame(4, $secretKey->getVersion());

        $encryptedSecretKey = $secretKey->encrypt(self::PASSPHRASE);
        $this->assertTrue($encryptedSecretKey->isEncrypted());

        $decryptedSecretKey = SecretKey::fromBytes($encryptedSecretKey->toBytes())->decrypt(self::PASSPHRASE);
        $this->assertSame($encryptedSecretKey->getFingerprint(), $decryptedSecretKey->getFingerprint());
        $this->assertSame(
            $secretKey->getKeyMaterial()->getPrivateKey()->toString('PKCS8'),
            $decryptedSecretKey->getKeyMaterial()->getPrivateKey()->toString('PKCS8')
        );
    }

    public function testGenerateEcdhSecretKeyCurve25519()
    {
        $secretKey = SecretKey::generate(
            KeyAlgorithm::Ecdh,
            curveOid: CurveOid::Curve25519
        );
        $this->assertFalse($secretKey->isEncrypted());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
        $this->assertSame(255, $secretKey->getKeyStrength());
        $this->assertSame(4, $secretKey->getVersion());

        $encryptedSecretKey = $secretKey->encrypt(self::PASSPHRASE);
        $this->assertTrue($encryptedSecretKey->isEncrypted());

        $decryptedSecretKey = SecretKey::fromBytes($encryptedSecretKey->toBytes())->decrypt(self::PASSPHRASE);
        $this->assertSame($encryptedSecretKey->getFingerprint(), $decryptedSecretKey->getFingerprint());
        $this->assertSame(
            $secretKey->getKeyMaterial()->getPrivateKey()->toString('MontgomeryPrivate'),
            $decryptedSecretKey->getKeyMaterial()->getPrivateKey()->toString('MontgomeryPrivate')
        );
    }

    public function testGenerateV5Key()
    {
        Config::setUseV5Key(true);

        $secretKey = SecretKey::generate(KeyAlgorithm::RsaEncryptSign);
        $this->assertFalse($secretKey->isEncrypted());
        $this->assertTrue($secretKey->getKeyMaterial()->isValid());
        $this->assertSame(2048, $secretKey->getKeyStrength());
        $this->assertSame(5, $secretKey->getVersion());

        Config::setUseV5Key(false);
    }

    public function testGenerateEcDsaSecretKeyException()
    {
        $this->expectException(\UnexpectedValueException::class);
        SecretKey::generate(
            KeyAlgorithm::EcDsa,
            curveOid: CurveOid::Ed25519
        );
    }

    public function testGenerateEcdhSecretKeyException()
    {
        $this->expectException(\UnexpectedValueException::class);
        SecretKey::generate(
            KeyAlgorithm::Ecdh,
            curveOid: CurveOid::Ed25519
        );
    }
}
