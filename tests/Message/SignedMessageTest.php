<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\Key\PublicKey;
use OpenPGP\Message\SignedMessage;
use OpenPGP\Message\Signature;
use OpenPGP\Packet\LiteralData;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OpenPGP signed message.
 */
class SignedMessageTest extends OpenPGPTestCase
{
    const LITERAL_TEXT = 'Hello PHP PG';

    public function testVerifyRsaCleartextSignedMessage()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/RsaPublicKey.asc')
        );

        $signedMessageData = <<<EOT
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello PHP PG
-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEE/FAE35RzJ3EH6qYFGE0NxPXFMrIFAmRtZboACgkQGE0NxPXF
MrJKWwgAhy0uYe/eXDgVB4UsqjO+Yx1AY0h1iy/m13oZD5tsCFH1NgUvATF9jc9a
fXur+aB5lEC4K3R2u4wZgLIit2BYdeAiA7QBjSMWTkgHdq2Vi2T7XA8GJRH8Al3I
b981duXxdPrhDOF0hj5Di5MPvb0FIXeY4ymg4AB4FO7LufzJUcMaq5FvMjG2L+YE
AuE249rYcztl7Tcy+SQgyj92C34Y022XYsJ0WEm32KPITXaCAm1MunquKKk2n3gu
ifTrk2aWYwkU9ANRZG32nkQ3VmT/mWKjl443TMOpNgUpqqm9f1hd/fw0IKSO7bwg
S24+wSO6Xx66VDS05uBQu811U5Bk2w==
=fnul
-----END PGP SIGNATURE-----
EOT;

        $signedMessage = SignedMessage::fromArmored($signedMessageData);
        $this->assertSame(self::LITERAL_TEXT, $signedMessage->getText());
        $this->assertTrue($signedMessage->getSignature() instanceof Signature);

        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('184d0dc4f5c532b2', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyDsaCleartextSignedMessage()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/DsaPublicKey.asc')
        );

        $signedMessageData = <<<EOT
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello PHP PG
-----BEGIN PGP SIGNATURE-----

iHUEAREIAB0WIQQ+V5E9X2zL25Ai997jsR1kIkigkgUCZG1t8wAKCRDjsR1kIkig
kgmaAPsFpOzSZcITK/k1npXel3LE5MisYJVcdFVR8Ai6BPlyDQD9FSLg5dVUBd64
zbJZjjdJXXhZunt1ntsp4MZeozbu5AM=
=w3Gh
-----END PGP SIGNATURE-----
EOT;

        $signedMessage = SignedMessage::fromArmored($signedMessageData);
        $this->assertSame(self::LITERAL_TEXT, $signedMessage->getText());
        $this->assertTrue($signedMessage->getSignature() instanceof Signature);

        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('e3b11d642248a092', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcP384CleartextSignedMessage()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcP384PublicKey.asc')
        );

        $signedMessageData = <<<EOT
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA384

Hello PHP PG
-----BEGIN PGP SIGNATURE-----

iJUEARMJAB0WIQQFwIVJLRT5CXbnwrayAtni6tpEDAUCZG1xHQAKCRCyAtni6tpE
DBU3AX9Bp4euH0PJxw0kfWFYvR/w5w3GzHJ6pV/k2/5D7MUy5yG/8/2f/bLz9+WD
F0D2qVcBfRgMCDIXJzHIiTnsje7Ki7VNVDuu/q7UkbJ1f03gkzHIFf94HSol2cEJ
GZs1GNJDIQ==
=ynbT
-----END PGP SIGNATURE-----
EOT;

        $signedMessage = SignedMessage::fromArmored($signedMessageData);
        $this->assertSame(self::LITERAL_TEXT, $signedMessage->getText());
        $this->assertTrue($signedMessage->getSignature() instanceof Signature);

        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('b202d9e2eada440c', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcBrainpoolCleartextSignedMessage()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPublicKey.asc')
        );

        $signedMessageData = <<<EOT
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello PHP PG
-----BEGIN PGP SIGNATURE-----

iHUEARMIAB0WIQQG/uMIXUbcAHwOwvAcvNBD20TF1gUCZG1xXQAKCRAcvNBD20TF
1muvAQCF/rdxEXj55CjPe+hl7qO5GTgkWG+9dxaa5Xmr+1pDEwEAo6Z0iJ7v80hb
QB/txJeN666mOiOXxJyyrNTOBoq+JUo=
=jYkC
-----END PGP SIGNATURE-----
EOT;

        $signedMessage = SignedMessage::fromArmored($signedMessageData);
        $this->assertSame(self::LITERAL_TEXT, $signedMessage->getText());
        $this->assertTrue($signedMessage->getSignature() instanceof Signature);

        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('1cbcd043db44c5d6', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcCurve25519CleartextSignedMessage()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PublicKey.asc')
        );

        $signedMessageData = <<<EOT
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Hello PHP PG
-----BEGIN PGP SIGNATURE-----

iHUEARYKAB0WIQQcQRbrK1jPoZbFfdu9/xNRYMVqCwUCZG1xngAKCRC9/xNRYMVq
C2zZAQC61SUhiU0zqHIz+s+tIWgZ+778TctqowYuKAcwbbab2AEAixR9ANSI7CVV
60ZSKNcfOeQot9CkHquggswe55yMsgw=
=Kt5L
-----END PGP SIGNATURE-----
EOT;

        $signedMessage = SignedMessage::fromArmored($signedMessageData);
        $this->assertSame(self::LITERAL_TEXT, $signedMessage->getText());
        $this->assertTrue($signedMessage->getSignature() instanceof Signature);

        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('bdff135160c56a0b', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyRsaDetachedSignature()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/RsaPublicKey.asc')
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

        $signature = Signature::fromArmored($signatureData);
        $verification = $signature->verify([$publicKey], LiteralData::fromText(self::LITERAL_TEXT))[0];
        $this->assertSame('184d0dc4f5c532b2', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyDsaDetachedSignature()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/DsaPublicKey.asc')
        );

        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iHUEAREIAB0WIQQ+V5E9X2zL25Ai997jsR1kIkigkgUCZG2CrQAKCRDjsR1kIkig
kneoAP489LyfdbNVnioC3zxMZp9x8oZ7JJrgcPnG1w9aWPwG5wD6A+OitTJwZZ9q
Y3EO7nnFH11dL7kVBegzI7sgpUCU3tM=
=m+3P
-----END PGP SIGNATURE-----
EOT;

        $signature = Signature::fromArmored($signatureData);
        $verification = $signature->verify([$publicKey], LiteralData::fromText(self::LITERAL_TEXT))[0];
        $this->assertSame('e3b11d642248a092', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcP384DetachedSignature()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcP384PublicKey.asc')
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

        $signature = Signature::fromArmored($signatureData);
        $verification = $signature->verify([$publicKey], LiteralData::fromText(self::LITERAL_TEXT))[0];
        $this->assertSame('b202d9e2eada440c', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcBrainpoolDetachedSignature()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPublicKey.asc')
        );

        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iHUEARMIAB0WIQQG/uMIXUbcAHwOwvAcvNBD20TF1gUCZG2DKgAKCRAcvNBD20TF
1gksAP9LYrhDj73q/+KOX9LX89EKucIfgNlmTIrNrrsjl3ZqrAD/Ub+cYenjoBTZ
d9EnxROMwB49IamBzqeeTtdcY7yzAPY=
=YOpZ
-----END PGP SIGNATURE-----
EOT;

        $signature = Signature::fromArmored($signatureData);
        $verification = $signature->verify([$publicKey], LiteralData::fromText(self::LITERAL_TEXT))[0];
        $this->assertSame('1cbcd043db44c5d6', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcCurve25519DetachedSignature()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PublicKey.asc')
        );

        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iHUEARYKAB0WIQQcQRbrK1jPoZbFfdu9/xNRYMVqCwUCZG2DWgAKCRC9/xNRYMVq
CyoSAQDLIMzAp/WoKxBnKAa0iejLSGFFoxeDvRyPNX+Et8OffwD/ePQeePF9ECRZ
68atBvRWzqhY2jiGZkSj7DyRh69zuAw=
=5g6W
-----END PGP SIGNATURE-----
EOT;

        $signature = Signature::fromArmored($signatureData);
        $verification = $signature->verify([$publicKey], LiteralData::fromText(self::LITERAL_TEXT))[0];
        $this->assertSame('bdff135160c56a0b', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }
}
