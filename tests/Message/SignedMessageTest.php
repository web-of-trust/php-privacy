<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\Type\SignatureInterface;
use OpenPGP\OpenPGP;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OpenPGP signed message.
 */
class SignedMessageTest extends OpenPGPTestCase
{
    const LITERAL_TEXT = "Hello PHP PG";

    public function testVerifyRsaCleartextSignedMessage()
    {
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

        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/RsaPublicKey.asc")
        );
        $signedMessage = OpenPGP::readSignedMessage($signedMessageData);
        $this->assertSame(self::LITERAL_TEXT, $signedMessage->getText());
        $this->assertTrue($signedMessage->getSignature() instanceof SignatureInterface);

        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame("184d0dc4f5c532b2", $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyDsaCleartextSignedMessage()
    {
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

        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/DsaPublicKey.asc")
        );
        $signedMessage = OpenPGP::readSignedMessage($signedMessageData);
        $this->assertSame(self::LITERAL_TEXT, $signedMessage->getText());
        $this->assertTrue($signedMessage->getSignature() instanceof SignatureInterface);

        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame("e3b11d642248a092", $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcP384CleartextSignedMessage()
    {
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

        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/EcP384PublicKey.asc")
        );
        $signedMessage = OpenPGP::readSignedMessage($signedMessageData);
        $this->assertSame(self::LITERAL_TEXT, $signedMessage->getText());
        $this->assertTrue($signedMessage->getSignature() instanceof SignatureInterface);

        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame("b202d9e2eada440c", $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcBrainpoolCleartextSignedMessage()
    {
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

        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/EcBrainpoolPublicKey.asc")
        );
        $signedMessage = OpenPGP::readSignedMessage($signedMessageData);
        $this->assertSame(self::LITERAL_TEXT, $signedMessage->getText());
        $this->assertTrue($signedMessage->getSignature() instanceof SignatureInterface);

        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame("1cbcd043db44c5d6", $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcCurve25519CleartextSignedMessage()
    {
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

        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/EcCurve25519PublicKey.asc")
        );
        $signedMessage = OpenPGP::readSignedMessage($signedMessageData);
        $this->assertSame(self::LITERAL_TEXT, $signedMessage->getText());
        $this->assertTrue($signedMessage->getSignature() instanceof SignatureInterface);

        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame("bdff135160c56a0b", $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testEd25519CleartextSignedMessage()
    {
        $publicKeyData = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----

EOT;

        $signedMessageData = <<<EOT
-----BEGIN PGP SIGNED MESSAGE-----

What we need from the grocery store:

- - tofu
- - vegetables
- - noodles

-----BEGIN PGP SIGNATURE-----

wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
NK2ay45cX1IVAQ==
-----END PGP SIGNATURE-----
EOT;

        $publicKey = OpenPGP::readPublicKey($publicKeyData);
        $signedMessage = OpenPGP::readSignedMessage($signedMessageData);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame(
            $publicKey->getKeyID(true),
            $verification->getKeyID(true)
        );
        $this->assertTrue($verification->isVerified());
    }
}
