<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\HashAlgorithm;
use OpenPGP\Packet\PublicKey;
use OpenPGP\Packet\SecretKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for signatures over SHA-3 hashes.
 */
class Sha3SigningTest extends OpenPGPTestCase
{
    const PASSPHRASE = "password";
    const LITERAL_TEXT = "Hello PHP PG";

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

    private static $ecdsaBrainpoolPublicKeyData = <<<EOT
BGRYXMETCSskAwMCCAEBBwIDBHKh5xdXoTfino6vulZBw4fl5lMtKgzXIeG9zhJuBInpE7gOlxes
07/JY2b9aIUph0fAku1xE+ljP5I/5pI5qrQ=
EOT;

    private static $ecdsaBrainpoolSecretKeyData = <<<EOT
BGRYXMETCSskAwMCCAEBBwIDBHKh5xdXoTfino6vulZBw4fl5lMtKgzXIeG9zhJuBInpE7gOlxes
07/JY2b9aIUph0fAku1xE+ljP5I/5pI5qrT+BwMCfKl8O5GIbj3/eruMvK1KnzWCGiQutGTYgQmP
u5aHJEwxtiXZFAHUTxoHgr3yd0IewonQL4Xxz25Zmp1iNL2VSyfPE5v8EDwgWcxCT9m1pQ==
EOT;

    public function testSignAndVerifyWithSha3()
    {
        // phpseclib names the SHA-3 hashes "sha3-256" and "sha3-512".
        $message = random_bytes(1024);
        $keys = [
            [self::$dsaSecretKeyData, self::$dsaPublicKeyData],
            [
                self::$ecdsaBrainpoolSecretKeyData,
                self::$ecdsaBrainpoolPublicKeyData,
            ],
        ];
        foreach ($keys as [$secretKeyData, $publicKeyData]) {
            $secretKey = SecretKey::fromBytes(
                base64_decode($secretKeyData)
            )->decrypt(self::PASSPHRASE);
            $publicKey = PublicKey::fromBytes(base64_decode($publicKeyData));
            foreach ([HashAlgorithm::Sha3_256, HashAlgorithm::Sha3_512] as $hash) {
                $signature = $secretKey->getSecretKeyMaterial()->sign(
                    $hash,
                    $message
                );
                $this->assertTrue(
                    $publicKey->getKeyMaterial()->verify($hash, $message, $signature)
                );
                $this->assertFalse(
                    $publicKey->getKeyMaterial()->verify(
                        $hash,
                        self::LITERAL_TEXT,
                        $signature
                    )
                );
            }
        }
    }
}
