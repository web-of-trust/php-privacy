<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Packet\PublicKey;
use OpenPGP\Packet\PublicSubkey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for public key packet.
 */
class PublicKeyTest extends OpenPGPTestCase
{
    public function testRSAPublicKey()
    {
        $data = <<<EOT
BGRUrD4BCACe8iv48dGvqnbOuPv1DnnrasH/NZ5bbpGHW0gSOXb4p2d7VcfA6hfoyq1yEuZ2VDzJ
WpkhVnKMF1Ytj7d8mtnGsTQ6NfGrV9jRhGIxAYIgiDjzuhIejzMrTR/RAh9aARPTuEayRXoShTEg
cQfZxIQKwwU5hE4PDZFhq0h/T83eImWidUZwt3zw6jWq29nDtmtR96x+xznG0utZrHsbkxNtuLpX
YlrMl9Lcz9vbntpK45aq35P3cfg5UEjCLj1TAq6LPFnfiwbQcNkbsTRsxPqWpX4J6v5ZabJIFGyd
K14eiohYTbp7Uvr/e3yRhTirWYz4KnJwuFOsemuSjSAGi3C5ABEBAAE=
EOT;
        $publicKey = PublicKey::fromBytes(base64_decode($data));
        $this->assertSame('fc5004df9473277107eaa605184d0dc4f5c532b2', bin2hex($publicKey->getFingerprint()));
        $this->assertSame('184d0dc4f5c532b2', bin2hex($publicKey->getKeyID()));
    }

    public function testRSAPublicSubkey()
    {
        $data = <<<EOT
BGRUrD4BCACyRTYWSBsXFtxLOmSp3RvaW13GRh8HJ4p7adVqJpDBsvo8iInDgBt542/aoWDGIESA
MHBMlyq+QLfPuvPg187E0nsi1fh+P6sJ+gjNjSibyDdsBjHW6ZDksoB7lO5NhSCnzo63kMlP7QBH
hvOWaZSUHG3JqCsdElDSHkMrHpVzpyco+bTs7XK/E1iS0kC32yE7ShV/rltvl8hUKZF1npG3ytka
fegaEYESkM32/vygrCOWNC1Tea7kWe1A0+/ZYbgPh3blorNGICkUqiKfST9Xq26Lb67Kc38Gxjij
X9LAnOoxEyCjmCv/+ajNIDvMSQOtnTCapLpRrhLlzjvIDtOnABEBAAE=
EOT;
        $publicSubkey = PublicSubkey::fromBytes(base64_decode($data));
        $this->assertSame('42badbbe0f2acabacd6cac7c4be1b3a621ef906f', bin2hex($publicSubkey->getFingerprint()));
        $this->assertSame('4be1b3a621ef906f', bin2hex($publicSubkey->getKeyID()));
    }

    public function testDSAPublicKey()
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
2R6iMnzQc3iIUX0Ns/vE3A==
EOT;
        $publicKey = PublicKey::fromBytes(base64_decode($data));
        $this->assertSame('3e57913d5f6ccbdb9022f7dee3b11d642248a092', bin2hex($publicKey->getFingerprint()));
        $this->assertSame('e3b11d642248a092', bin2hex($publicKey->getKeyID()));
    }

    public function testElGamalPublicSubkey()
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
ZSgDj7aW2N0nvDT5
EOT;
        $publicSubkey = PublicSubkey::fromBytes(base64_decode($data));
        $this->assertSame('420a452a98ea130c7747e0b2c0453c8aabe775db', bin2hex($publicSubkey->getFingerprint()));
        $this->assertSame('c0453c8aabe775db', bin2hex($publicSubkey->getKeyID()));
    }

    public function testECDSAp384PublicKey()
    {
        $data = <<<EOT
BGRYd7UTBSuBBAAiAwME3Z/lmJrDGnYHvT7xe5ei8xFfsCsrH+6AjmSftcJEYCCTy4CupXlvp5wb
FLQ2klduC2c09LzjULVFn4uQKdMacYb7X0UjI2q6MLGP1fpmg7mq4F8myVJx6lkvpHK44xDh
EOT;
        $publicKey = PublicKey::fromBytes(base64_decode($data));
        $this->assertSame('05c085492d14f90976e7c2b6b202d9e2eada440c', bin2hex($publicKey->getFingerprint()));
        $this->assertSame('b202d9e2eada440c', bin2hex($publicKey->getKeyID()));
    }

    public function testECDHp384PublicSubkey()
    {
        $data = <<<EOT
BGRYd7USBSuBBAAiAwMEEWHAaBdPHihwch9e3b4VqOB89WeHI6fGWDLpKj6bJ/ME1VbDPhf0DN0N
c1s1wntRUFb9OjS06I8YQVBIPdyegmsMZj9J/fa0qFkd2r3siXb2x3zGqsxe1lvrYDVj9gDYAwEJ
CQ==
EOT;
        $publicSubkey = PublicSubkey::fromBytes(base64_decode($data));
        $this->assertSame('7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6', bin2hex($publicSubkey->getFingerprint()));
        $this->assertSame('c0b7b9c6bf5824b6', bin2hex($publicSubkey->getKeyID()));
    }

    public function testECDSAbrainpoolP256PublicKey()
    {
        $data = <<<EOT
BGRYXMETCSskAwMCCAEBBwIDBHKh5xdXoTfino6vulZBw4fl5lMtKgzXIeG9zhJuBInpE7gOlxes
07/JY2b9aIUph0fAku1xE+ljP5I/5pI5qrQ=
EOT;
        $publicKey = PublicKey::fromBytes(base64_decode($data));
        $this->assertSame('06fee3085d46dc007c0ec2f01cbcd043db44c5d6', bin2hex($publicKey->getFingerprint()));
        $this->assertSame('1cbcd043db44c5d6', bin2hex($publicKey->getKeyID()));
    }

    public function testECDHbrainpoolP256PublicSubkey()
    {
        $data = <<<EOT
BGRYXMESCSskAwMCCAEBBwIDBINvienMnFyJJCblEBJ2J9sBZ/hCAHGLbgDZPCC+mTLqDJJx47Sr
B3ZgWmrx1NRoT2pQfD2qqYo8jQJK8XlgyqIDAQgH
EOT;
        $publicSubkey = PublicSubkey::fromBytes(base64_decode($data));
        $this->assertSame('457b5979545fba09be179db808a55bdb1d673d5d', bin2hex($publicSubkey->getFingerprint()));
        $this->assertSame('08a55bdb1d673d5d', bin2hex($publicSubkey->getKeyID()));
    }


    public function testEdDSACurve25519PublicKey()
    {
        $data = <<<EOT
BGRYXQUWCSsGAQQB2kcPAQEHQLvR0VoiVSt3+xzxSSQrR7/yrMzQG8OXueMhIkQb0UPM
EOT;
        $publicKey = PublicKey::fromBytes(base64_decode($data));
        $this->assertSame('1c4116eb2b58cfa196c57ddbbdff135160c56a0b', bin2hex($publicKey->getFingerprint()));
        $this->assertSame('bdff135160c56a0b', bin2hex($publicKey->getKeyID()));
    }

    public function testECDHCurve25519PublicSubkey()
    {
        $data = <<<EOT
BGRYXQUSCisGAQQBl1UBBQEBB0BCbUFNqFZKpFLBB339cZrp7udovohvVMiG7qP9+ij6AQMBCAc=
EOT;
        $publicSubkey = PublicSubkey::fromBytes(base64_decode($data));
        $this->assertSame('8efa53a375fc569aa9ca564a044eac93f0b69ea0', bin2hex($publicSubkey->getFingerprint()));
        $this->assertSame('044eac93f0b69ea0', bin2hex($publicSubkey->getKeyID()));
    }
}
