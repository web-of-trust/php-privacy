<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\Packet\LiteralData;
use OpenPGP\OpenPGP;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OpenPGP signature.
 */
class SignatureTest extends OpenPGPTestCase
{
    const LITERAL_TEXT = "Hello PHP PG";

    public function testVerifyRsaDetachedSignature()
    {
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/RsaPublicKey.asc")
        );

        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEE/FAE35RzJ3EH6qYFGE0NxPXFMrIFAmRteUYACgkQGE0NxPXF
MrKi8Qf+JbAo/Pyd9cJo+LUK46sMQpnNVA/fx70BRzlizjN7J4le023eH2q9w8P8
l7ZkDsLXnYRmGT1MKREJ5L6AfKuFBcQliKnMNE+De5HWe7RoZF+o9HnbJA2lGk+L
JEYLk+KacxJh3F+r7qp291tfVO147FqFQMy/BmyZ/j4N5tJ2zCeEDTP71YodpQ8x
dEuzwkzx70EGDNJi3kZwwbuFbyl4fGOZUMrTa1B2gYWB9kiWDsmmf1/PWzEasAWd
LUtBiGHLj5wItiAhT3QpbcjkInIK3S4qLHXWBStzWnkNImtxEspJBTzVpGdi5E1x
8YOcQEQm5lh2VZKoSUUZWS4fL2QmDw==
=HZAt
-----END PGP SIGNATURE-----
EOT;

        $signature = OpenPGP::readSignature($signatureData);
        $verification = $signature->verify(
            [$publicKey],
            LiteralData::fromText(self::LITERAL_TEXT)
        )[0];
        $this->assertSame("184d0dc4f5c532b2", $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyDsaDetachedSignature()
    {
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/DsaPublicKey.asc")
        );

        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iHUEAREIAB0WIQQ+V5E9X2zL25Ai997jsR1kIkigkgUCZG2CrQAKCRDjsR1kIkig
kneoAP489LyfdbNVnioC3zxMZp9x8oZ7JJrgcPnG1w9aWPwG5wD6A+OitTJwZZ9q
Y3EO7nnFH11dL7kVBegzI7sgpUCU3tM=
=m+3P
-----END PGP SIGNATURE-----
EOT;

        $signature = OpenPGP::readSignature($signatureData);
        $verification = $signature->verify(
            [$publicKey],
            LiteralData::fromText(self::LITERAL_TEXT)
        )[0];
        $this->assertSame("e3b11d642248a092", $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcP384DetachedSignature()
    {
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/EcP384PublicKey.asc")
        );

        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iJUEARMJAB0WIQQFwIVJLRT5CXbnwrayAtni6tpEDAUCZG2C7gAKCRCyAtni6tpE
DD8hAX47oeQbDCDll9NbFL/xqPIQ1znvhE1pLGWPERmjgBo2Vu8DhyVWxrpXK/dH
1WhG9bkBf0ek1prVD0qOHogUfrC20GLZNmICf/7Rv29wzowcDWQ0mUkE+K3xCAqf
xRtw3Ue2xQ==
=iwlD
-----END PGP SIGNATURE-----
EOT;

        $signature = OpenPGP::readSignature($signatureData);
        $verification = $signature->verify(
            [$publicKey],
            LiteralData::fromText(self::LITERAL_TEXT)
        )[0];
        $this->assertSame("b202d9e2eada440c", $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcBrainpoolDetachedSignature()
    {
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/EcBrainpoolPublicKey.asc")
        );

        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iHUEARMIAB0WIQQG/uMIXUbcAHwOwvAcvNBD20TF1gUCZG2DKgAKCRAcvNBD20TF
1gksAP9LYrhDj73q/+KOX9LX89EKucIfgNlmTIrNrrsjl3ZqrAD/Ub+cYenjoBTZ
d9EnxROMwB49IamBzqeeTtdcY7yzAPY=
=YOpZ
-----END PGP SIGNATURE-----
EOT;

        $signature = OpenPGP::readSignature($signatureData);
        $verification = $signature->verify(
            [$publicKey],
            LiteralData::fromText(self::LITERAL_TEXT)
        )[0];
        $this->assertSame("1cbcd043db44c5d6", $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcCurve25519DetachedSignature()
    {
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/EcCurve25519PublicKey.asc")
        );

        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iHUEARYKAB0WIQQcQRbrK1jPoZbFfdu9/xNRYMVqCwUCZG2DWgAKCRC9/xNRYMVq
CyoSAQDLIMzAp/WoKxBnKAa0iejLSGFFoxeDvRyPNX+Et8OffwD/ePQeePF9ECRZ
68atBvRWzqhY2jiGZkSj7DyRh69zuAw=
=5g6W
-----END PGP SIGNATURE-----
EOT;

        $signature = OpenPGP::readSignature($signatureData);
        $verification = $signature->verify(
            [$publicKey],
            LiteralData::fromText(self::LITERAL_TEXT)
        )[0];
        $this->assertSame("bdff135160c56a0b", $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }
}
