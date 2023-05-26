<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\Enum\{CompressionAlgorithm, LiteralFormat};
use OpenPGP\Key\{PrivateKey, PublicKey};
use OpenPGP\Message\{LiteralMessage, Signature};
use OpenPGP\Packet\LiteralData;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OpenPGP literal message.
 */
class LiteralMessageTest extends OpenPGPTestCase
{
    const LITERAL_DATA = "Hello PHP PG\n";
    const PASSPHRASE   = 'password'; 

    private static string $encryptedMessageData = <<<EOT
-----BEGIN PGP MESSAGE-----

hQEMA0vhs6Yh75BvAQgArD5vV3iXN2TeWnRNA+4jkVbv5vARrKG/3Jr6Y8igKo3x
QVqgbCtk9CDkwCE94npW7mQA+gS+1iXy2OEhjrRgnJ8q6X5EeqUo7XkIkv6Z36L4
qwqBLIgdz1bt72CHonmtnxjow/dQNLV30HOZymqRk94xXxqbdUc16lk3AekkBoYW
YS9LH7r4JdEIfPMzpfisIWLWAiyZpt4y69rX9b1awwTcjIFhShwzmBi0KLmHsCi7
4VyoRxsploT9Gg17Rk0EoqG1miYPLR2Bpz7Ww+ipx9topU9LAaMUzUoZjEMJabkv
gxSm2NJJOLGiRbD4/Tt8c0iDJ9XYYSMuwZUEZ2LsO4UCDgPARTyKq+d12xAH+wUj
lGRALyODOS603CG//coGtqtntrSuvEDZhxoy7yaE3jaCk7HMjspnzjQA3XnC0tef
LYNxfiTy8RI1yWR/samDTUj/5dA2GWPRW/+mRFBILosW/BOSCAC1yDo9GCuJ/qk7
gt/f8m4pBU3jVnHrPSQsVRCg2YpemaV+t/4C88OFjhhorFxUBleKksrFqJocjG8w
kdLUobkcV09xivNbTPOdZFwqcMaaHBw87X58hG3BCF2c+62nXBS52p9Jdivg6M8P
1dEdw8wEUFTlGbbMdX8JReZAdsMUuQfcju/w/oFrn9aMH0s2HnM6PqFK0qYCdpNu
v77GNgbCqnOUfWnHSfcH/Rjy5u2nFgIYhzMADo5084F0SWB7v6FByKTOMUDpKvZm
d4m0zaaiMSgCDwedC3HiHAjj6k8iMG+86vbuqSwB3PWAKbKZI6+RHCVu1eE9A0A1
w76AXLaTQhcqM737PffkSN9Q+zDJNoVeTcaG69m7UNuh62QwVPUxGLoXcml8ny6Z
ThYi1u9hF5CdD28rnCGox+UFKMDH0s8ySzH8Gdib4Je+FaihNPDBEGCuZaK01wxh
XrvK3+1089T2W6ODZ5ZLFllRaHMkmVGYZd1ZXctRFlGxK5YEfrFhnUzSrs0fJTwP
Aupu8fxpzcNhithT5HViwxKIUo8SpZNSN5zMpMXHBTuEngPAt7nGv1gkthIDAwT3
bAb8huf2u13ZnYQxVqPQQo4Idwi7iO06g4+ByaT7MBY2953z4UL3rNOIE2okTCAL
T1sO7WRar9ztTrO1EMPgH5n795CFqwBCtvBH89IbNe/IazFXqOiERdI/jI51OQ4w
XH1wRPkYuyxpIuOd6sYqAiXlItnEm7uUqThwGKQdMkskRNvdg9LuxK8z8J+iPeFH
hH4DCKVb2x1nPV0SAgMES8/Id23ZoJF1RthVupEL/O1BNGxKjCnT+DMwhzps481C
na6dlguwJiLmwhC41C5q5g9gF4pwi794jHH/N8NusDCl7nUMtiY1LkXCdmHWWgfH
af0zmNk2qlpA1OPptbgUsmo5R3RtDxtrgoVi6leeccmEXgMETqyT8LaeoBIBB0DE
lEPiRMafSoDb/Y7f4W1BA/AOYT5CH0fN4AcUm1U1PjCYMQAer1hmQdDQ5ze0whhX
01cAvmkKVJlucyo4/BVYqjpGKiNH1KAnSVwZ1V/Uv8+MLgQJAwLFRe+hwBVgPv9b
ZFGh4SowvMSVsTeojUZsa8hqApqEMkqI/Xjt6EarRv3SSAGYMRuSQ3cKqbrujRrN
OTo1ts4yde3TciQw637tmDHXX694Nt7EhUkujoYpVdc1gAnyc3MUZd9YhZ0lGZZH
XmkILgTV8jsTfQ==
=Qs55
-----END PGP MESSAGE-----
EOT;


    public function testVerifyRsaSignedMessage()
    {
        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----

owEBWgGl/pANAwAIARhNDcT1xTKyAcsTYgBkcAjISGVsbG8gUEhQIFBHCokBMwQA
AQgAHRYhBPxQBN+UcydxB+qmBRhNDcT1xTKyBQJkcAjIAAoJEBhNDcT1xTKyD5IH
/Rjx4qKJyRkH0g+Gn5XEBFp/HlahltPeYAWzRAhgEPHfCtHLg4MjYRN4QnyqwLTq
U2bICqzD3x0QIYdS5Z9fkAmtIO9ZsnJvv9XYdrxIMCrePkKM7sT/l31M0sFHvowv
lPvb9DSkbM57zP/sd16CjHBVVARD4g330BQ4aoXL9T1ngoXqAV7iZdQSxT2hmAwf
I5qDjicvANuKyIfE5k+Zsg4k6mnSsDv+D0vGt8cOx6OgY1j4E9XK4ipNdp2dTt5J
canceovt1cRU7VUluanqpAc5eOecodUL6LaY2LZEjnFZWjw7BP2eCh0FZKx8Og5U
koIAxNXOxaRF4vybpbI7FWQ=
=/rPl
-----END PGP MESSAGE-----
EOT;

        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/RsaPublicKey.asc')
        );
        $message = LiteralMessage::fromArmored($messageData);
        // var_dump($message->getLiteralData()->getData());exit;
        $this->assertSame(self::LITERAL_DATA, $message->getLiteralData()->getData());
        $this->assertTrue($message->getSignature() instanceof Signature);

        $verification = $message->verify([$publicKey])[0];
        $this->assertSame('184d0dc4f5c532b2', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyDsaSignedMessage()
    {
        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----

owGbwMvMwCH4eKNsipLHgkmMp4WTGFIKuHs9UnNy8hUCPAIUAty5OkpZGAQ5GGTF
FFnswifaxuecvj1B6fs9mCZWJpAOBi5OAZjIy3UM/+M4F12pX+B0JoE/qqiBM697
34NPPIrd01an7ZU5cDHm7mWGf1o/NXhbri9adtLvwvm5VxcXSfl82xFgtnmFlJ1u
4L2Xjy8DAA==
=/m2m
-----END PGP MESSAGE-----
EOT;

        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/DsaPublicKey.asc')
        );
        $message = LiteralMessage::fromArmored($messageData);
        $this->assertSame(self::LITERAL_DATA, $message->getLiteralData()->getData());
        $this->assertTrue($message->getSignature() instanceof Signature);

        $verification = $message->verify([$publicKey])[0];
        $this->assertSame('e3b11d642248a092', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcP384SignedMessage()
    {
        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----

owGbwMvMwCm8ienmo1e3XHgYTwsnMaQUcP/0SM3JyVcI8AhQCHDn6pjKwiDMySAr
psjCeqDVU1fkJ2fZ80PbYJpYmUA6GLg4BWAiO5YzNhwouNc15yt7gfLVVx4CtQ8S
v+6aFjDPdbvdflERe4fNhsX72z+Y9qemeK0wkPz7+MiZi4wNbR0qxnMcM2/1fi2e
olN2PbFm8ibP8kmmPQc+OM3z+u23f89FNfb9Lxr1/As0POP/HcoBAA==
=xVkT
-----END PGP MESSAGE-----
EOT;

        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcP384PublicKey.asc')
        );
        $message = LiteralMessage::fromArmored($messageData);
        $this->assertSame(self::LITERAL_DATA, $message->getLiteralData()->getData());
        $this->assertTrue($message->getSignature() instanceof Signature);

        $verification = $message->verify([$publicKey])[0];
        $this->assertSame('b202d9e2eada440c', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcBrainpoolSignedMessage()
    {
        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----

owGbwMvMwCEss+eC822Xo9cYTwsnMaQU8Bh4pObk5CsEeAQoBLhzdZSyMAhzMMiK
KbKw/XvMEet2h6GG79AHmCZWJpAOBi5OAZjIfmeG/2UXlWVvvuz0ebJvv0LQYYXP
X2NXOEjMr1qhGTSv74fzjTcMf3jbFFOOi1zPX3QpdULoC6NJ6xLePdh4LrSxsGTV
v2OXGRgB
=SqQw
-----END PGP MESSAGE-----
EOT;

        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPublicKey.asc')
        );
        $message = LiteralMessage::fromArmored($messageData);
        $this->assertSame(self::LITERAL_DATA, $message->getLiteralData()->getData());
        $this->assertTrue($message->getSignature() instanceof Signature);

        $verification = $message->verify([$publicKey])[0];
        $this->assertSame('1cbcd043db44c5d6', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcCurve25519SignedMessage()
    {
        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----

owGbwMvMwCW2979wYMLRLG7G08JJDCkFPGkeqTk5+QoBHgEKAe5cHaUsDGJcDLJi
iiwyjmKvtSPOL5x2tPY2TBMrE0gHAxenAEykIZ2R4e1X2xksp8+WmW3Yf2hOdWTt
6p91S3T++H9sCzP+vMjrRzLD//Br7RNCWm4rMlWdaPr6d7rWZNVPKUfbGt6VfKtv
fB/SzQ4A
=/04O
-----END PGP MESSAGE-----
EOT;

        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PublicKey.asc')
        );
        $message = LiteralMessage::fromArmored($messageData);
        $this->assertSame(self::LITERAL_DATA, $message->getLiteralData()->getData());
        $this->assertTrue($message->getSignature() instanceof Signature);

        $verification = $message->verify([$publicKey])[0];
        $this->assertSame('bdff135160c56a0b', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyRsaDetachedSignature()
    {
        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iQEzBAABCAAdFiEE/FAE35RzJ3EH6qYFGE0NxPXFMrIFAmRwD3oACgkQGE0NxPXF
MrJwRggAgdak9P9sLQE5rS0hfB9s5qp0jucZSbUy3W48KIsWjEqZ4PA3DE4Bqg4/
FojKz5S/H4SkEfyh8k8GzRvlGByXU3ZG8ZFxeYBRsNvWvw7bqgkPL5fZri+JcI7k
C8wA5bEJ0EWcYe3AeL6giyuRlujnJmgILApmspDwywtmNUT3Fo5jZVAbjgHbkkYj
DNjsF/5qkhXwQ2GJ2xaeSc6yDMM2kZW4OyvTJ9l94V7KtZYRBgZmEuJ7aRINhBuw
U8m/lGFVBm0Gw2fIizyjOwt83EGmotNQijtiZvRMrFUSq03WbYQMXnvkJt4YlvGh
Mz4sU7yMAc9UOEiLw0lCVD21um9QaA==
=ZI2O
-----END PGP SIGNATURE-----
EOT;

        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/RsaPublicKey.asc')
        );
        $message = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);
        $signature = Signature::fromArmored($signatureData);

        $verification = $message->verifyDetached([$publicKey], $signature)[0];
        $this->assertSame('184d0dc4f5c532b2', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyDsaDetachedSignature()
    {
        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iHUEABEIAB0WIQQ+V5E9X2zL25Ai997jsR1kIkigkgUCZHARcQAKCRDjsR1kIkig
krwrAQCktk6T037drM8kKirZ01AzMvmyhoklbeIHLaTmfVnoswEAje8ylMXGxRna
p4iTK8BfckODOHP9MPV3+gOunYR+sYs=
=OxoL
-----END PGP SIGNATURE-----
EOT;

        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/DsaPublicKey.asc')
        );
        $message = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);
        $signature = Signature::fromArmored($signatureData);

        $verification = $message->verifyDetached([$publicKey], $signature)[0];
        $this->assertSame('e3b11d642248a092', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcP384DetachedSignature()
    {
        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iJUEABMJAB0WIQQFwIVJLRT5CXbnwrayAtni6tpEDAUCZHARvQAKCRCyAtni6tpE
DHosAYDKonlUioxmVItC51xlZpVzwCRiRKj72RG7xFM5wx7BbbkUSDPpLcelLhPJ
58nQtpkBgIwAdcF3Q71GpLbwXCuK/JZyRJa53t6GkM/w99cYIk219A/Gi/CYApq6
yvVtUIpkjw==
=BjK9
-----END PGP SIGNATURE-----
EOT;

        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcP384PublicKey.asc')
        );
        $message = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);
        $signature = Signature::fromArmored($signatureData);

        $verification = $message->verifyDetached([$publicKey], $signature)[0];
        $this->assertSame('b202d9e2eada440c', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcBrainpoolDetachedSignature()
    {
        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iHUEABMIAB0WIQQG/uMIXUbcAHwOwvAcvNBD20TF1gUCZHAR7wAKCRAcvNBD20TF
1idKAQCikHK8U4JRZKYL4CbRkZy7vBmXHGtTAWC46ZjLG6kK1wEAiedU9TPTApaz
K1rxwEcNf7raFJ8qt0SLehSchqD5YGQ=
=ldQS
-----END PGP SIGNATURE-----
EOT;

        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPublicKey.asc')
        );
        $message = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);
        $signature = Signature::fromArmored($signatureData);

        $verification = $message->verifyDetached([$publicKey], $signature)[0];
        $this->assertSame('1cbcd043db44c5d6', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testVerifyEcCurve25519DetachedSignature()
    {
        $signatureData = <<<EOT
-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQQcQRbrK1jPoZbFfdu9/xNRYMVqCwUCZHASHgAKCRC9/xNRYMVq
C6/9AQD7q67ElnunMqe82hsOIjSeZdx/k4XgvF5jnIdOt9FndgD/aR4CwGCM0mY2
G5C7hirK1TGRFNn21JYEMGe8v1WCBwg=
=E9Gy
-----END PGP SIGNATURE-----
EOT;

        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PublicKey.asc')
        );
        $message = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);
        $signature = Signature::fromArmored($signatureData);

        $verification = $message->verifyDetached([$publicKey], $signature)[0];
        $this->assertSame('bdff135160c56a0b', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testSignRsaMessage()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/RsaPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/RsaPublicKey.asc')
        );
        $literalMessage = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);

        $signedMessage = $literalMessage->sign([$privateKey]);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('184d0dc4f5c532b2', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());

        $signedMessage = LiteralMessage::fromArmored($signedMessage->armor());
        $this->assertSame(self::LITERAL_DATA, $signedMessage->getLiteralData()->getData());
        $this->assertTrue($signedMessage->getSignature() instanceof Signature);

        $signature = $literalMessage->signDetached([$privateKey]);
        $verification = $literalMessage->verifyDetached([$publicKey], $signature)[0];
        $this->assertSame('184d0dc4f5c532b2', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testSignDsaMessage()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/DsaPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/DsaPublicKey.asc')
        );
        $literalMessage = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);

        $signedMessage = $literalMessage->sign([$privateKey]);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('e3b11d642248a092', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());

        $signedMessage = LiteralMessage::fromArmored($signedMessage->armor());
        $this->assertSame(self::LITERAL_DATA, $signedMessage->getLiteralData()->getData());
        $this->assertTrue($signedMessage->getSignature() instanceof Signature);

        $signature = $literalMessage->signDetached([$privateKey]);
        $verification = $literalMessage->verifyDetached([$publicKey], $signature)[0];
        $this->assertSame('e3b11d642248a092', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testSignEcP384Message()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcP384PrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcP384PublicKey.asc')
        );
        $literalMessage = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);

        $signedMessage = $literalMessage->sign([$privateKey]);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('b202d9e2eada440c', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());

        $signedMessage = LiteralMessage::fromArmored($signedMessage->armor());
        $this->assertSame(self::LITERAL_DATA, $signedMessage->getLiteralData()->getData());
        $this->assertTrue($signedMessage->getSignature() instanceof Signature);

        $signature = $literalMessage->signDetached([$privateKey]);
        $verification = $literalMessage->verifyDetached([$publicKey], $signature)[0];
        $this->assertSame('b202d9e2eada440c', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testSignEcBrainpoolMessage()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPublicKey.asc')
        );
        $literalMessage = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);

        $signedMessage = $literalMessage->sign([$privateKey]);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('1cbcd043db44c5d6', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());

        $signedMessage = LiteralMessage::fromArmored($signedMessage->armor());
        $this->assertSame(self::LITERAL_DATA, $signedMessage->getLiteralData()->getData());
        $this->assertTrue($signedMessage->getSignature() instanceof Signature);

        $signature = $literalMessage->signDetached([$privateKey]);
        $verification = $literalMessage->verifyDetached([$publicKey], $signature)[0];
        $this->assertSame('1cbcd043db44c5d6', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testSignEcCurve25519Message()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PublicKey.asc')
        );
        $literalMessage = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);

        $signedMessage = $literalMessage->sign([$privateKey]);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('bdff135160c56a0b', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());

        $signedMessage = LiteralMessage::fromArmored($signedMessage->armor());
        $this->assertSame(self::LITERAL_DATA, $signedMessage->getLiteralData()->getData());
        $this->assertTrue($signedMessage->getSignature() instanceof Signature);

        $signature = $literalMessage->signDetached([$privateKey]);
        $verification = $literalMessage->verifyDetached([$publicKey], $signature)[0];
        $this->assertSame('bdff135160c56a0b', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testDecryptEncryptedMessage()
    {
        $message = LiteralMessage::fromArmored(self::$encryptedMessageData);

        $decryptedMessage = $message->decrypt(passwords: [self::PASSPHRASE]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());

        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/RsaPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $message->decrypt([$privateKey]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());

        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/DsaPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $message->decrypt([$privateKey]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());

        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcP384PrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $message->decrypt([$privateKey]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());

        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $message->decrypt([$privateKey]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());

        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $message->decrypt([$privateKey]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());
    }

    public function testEncryptCompressMessage()
    {
        $rsaPublicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/RsaPublicKey.asc')
        );
        $dsaPublicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/DsaPublicKey.asc')
        );
        $ecP384PublicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcP384PublicKey.asc')
        );
        $ecBrainpoolPublicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPublicKey.asc')
        );
        $ecCurve25519PublicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PublicKey.asc')
        );

        $message = new LiteralMessage([
            new LiteralData(self::LITERAL_DATA, LiteralFormat::Binary)
        ]);
        $encryptedMessage = $message->compress(CompressionAlgorithm::BZip2)->encrypt(
            [
                $rsaPublicKey,
                $dsaPublicKey,
                $ecP384PublicKey,
                $ecBrainpoolPublicKey,
                $ecCurve25519PublicKey,
            ],
            [self::PASSPHRASE]
        );

        $decryptedMessage = $encryptedMessage->decrypt(passwords: [self::PASSPHRASE]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());

        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/RsaPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());

        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/DsaPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());

        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcP384PrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());

        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());

        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());
    }
}
