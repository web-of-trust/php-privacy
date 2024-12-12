<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\Key\{PrivateKey, PublicKey};
use OpenPGP\Type\AeadEncryptedDataPacketInterface as AeadEncryptedData;
use OpenPGP\OpenPGP;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OpenPGP literal message.
 */
class EncryptedMessageTest extends OpenPGPTestCase
{
    const LITERAL_DATA = "Hello PHP PG\n";
    const PASSPHRASE = "password";

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

    public function testDecryptEncryptedMessage()
    {
        $encryptedMessage = OpenPGP::readEncryptedMessage(
            self::$encryptedMessageData
        );

        $decryptedMessage = $encryptedMessage->decrypt(
            passwords: [self::PASSPHRASE]
        );
        $this->assertSame(
            self::LITERAL_DATA,
            $decryptedMessage->getLiteralData()->getData()
        );

        $privateKey = PrivateKey::fromArmored(
            file_get_contents("tests/Data/RsaPrivateKey.asc")
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(
            self::LITERAL_DATA,
            $decryptedMessage->getLiteralData()->getData()
        );

        $privateKey = PrivateKey::fromArmored(
            file_get_contents("tests/Data/DsaPrivateKey.asc")
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(
            self::LITERAL_DATA,
            $decryptedMessage->getLiteralData()->getData()
        );

        $privateKey = PrivateKey::fromArmored(
            file_get_contents("tests/Data/EcP384PrivateKey.asc")
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(
            self::LITERAL_DATA,
            $decryptedMessage->getLiteralData()->getData()
        );

        $privateKey = PrivateKey::fromArmored(
            file_get_contents("tests/Data/EcBrainpoolPrivateKey.asc")
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(
            self::LITERAL_DATA,
            $decryptedMessage->getLiteralData()->getData()
        );

        $privateKey = PrivateKey::fromArmored(
            file_get_contents("tests/Data/EcCurve25519PrivateKey.asc")
        )->decrypt(self::PASSPHRASE);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(
            self::LITERAL_DATA,
            $decryptedMessage->getLiteralData()->getData()
        );
    }

    public function testDecryptAepdMessage()
    {
        $encryptedMessageData = <<<EOT
-----BEGIN PGP MESSAGE-----

jD0FBwIDCPTU9TrcG/ef/xFWqji4GJrUyUl69Pv5jAx2Kqji9g4nBGu5RXlYoY/8
cTHw+kww2UtrXVkeUDQI1EwBBwIQtSJxPQCq1Mg7/Ashm2BQxiCRO1DtO6TN/+sy
58ZOoB5PVTW8IcABVZi/8mtZtqY02rYfTcXYiyVQP9Qx0gnqM1hCCQp/tZYX
=id4U
-----END PGP MESSAGE-----
EOT;

        $encryptedMessage = OpenPGP::readEncryptedMessage(
            $encryptedMessageData
        );
        $this->assertTrue(
            $encryptedMessage->getEncryptedPacket() instanceof AeadEncryptedData
        );

        $decryptedMessage = $encryptedMessage->decrypt(
            passwords: [self::PASSPHRASE]
        );
        $this->assertSame(
            self::LITERAL_DATA,
            $decryptedMessage->getLiteralData()->getData()
        );
    }

    public function testDecryptX25519AeadOcbMessage()
    {
        $privatekeyData = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----
EOT;

        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----

wV0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmHzxjV8bU/gXzO
WgBM85PMiVi93AZfJfhK9QmxfdNnZBjeo1VDeVZheQHgaVf7yopqR6W1FT6NOrfS
aQIHAgZhZBZTW+CwcW1g4FKlbExAf56zaw76/prQoN+bAzxpohup69LA7JW/Vp0l
yZnuSj3hcFj0DfqLTGgr4/u717J+sPWbtQBfgMfG9AOIwwrUBqsFE9zW+f1zdlYo
bhF30A+IitsxxA==
-----END PGP MESSAGE-----
EOT;

        $privateKey = PrivateKey::fromArmored($privatekeyData);
        $encryptedMessage = OpenPGP::readEncryptedMessage($messageData);
        $decryptedMessage = $encryptedMessage->decrypt([$privateKey]);
        $this->assertSame(
            "Hello, world!",
            $decryptedMessage->getLiteralData()->getData()
        );
    }

    public function testDecryptAeadEaxMessage()
    {
        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----

w0AGHgcBCwMIpa5XnR/F2Cv/aSJPkZmTs1Bvo7WaanPP+MXvxfQcV/tU4cImgV14
KPX5LEVOtl6+AKtZhsaObnxV0mkCBwEGn/kOOzIZZPOkKRPI3MZhkyUBUifvt+rq
pJ8EwuZ0F11KPSJu1q/LnKmsEiwUcOEcY9TAqyQcapOK1Iv5mlqZuQu6gyXeYQR1
QCWKt5Wala0FHdqW6xVDHf719eIlXKeCYVRuM5o=
-----END PGP MESSAGE-----
EOT;

        $encryptedMessage = OpenPGP::readEncryptedMessage($messageData);
        $decryptedMessage = $encryptedMessage->decrypt(
            passwords: [self::PASSPHRASE]
        );
        $this->assertSame(
            "Hello, world!",
            $decryptedMessage->getLiteralData()->getData()
        );
        $this->assertSame(
            hex2bin("3881bafe985412459b86c36f98cb9a5e"),
            $encryptedMessage->getSessionKey()->getEncryptionKey()
        );
    }

    public function testDecryptAeadOcbMessage()
    {
        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----

wz8GHQcCCwMIVqKY0vXjZFP/z8xcEWZO2520JZDX3EawckG2EsOBLP/76gDyNHsl
ZBEj+IeuYNT9YU4IN9gZ02zSaQIHAgYgpmH3MfyaMDK1YjMmAn46XY21dI6+/wsM
WRDQns3WQf+f04VidYA1vEl1TOG/P/+n2tCjuBBPUTPPQqQQCoPu9MobSAGohGv0
K82nyM6dZeIS8wHLzZj9yt5pSod61CRzI/boVw==
-----END PGP MESSAGE-----
EOT;

        $encryptedMessage = OpenPGP::readEncryptedMessage($messageData);
        $decryptedMessage = $encryptedMessage->decrypt(
            passwords: [self::PASSPHRASE]
        );
        $this->assertSame(
            "Hello, world!",
            $decryptedMessage->getLiteralData()->getData()
        );
        $this->assertSame(
            hex2bin("28e79ab82397d3c63de24ac217d7b791"),
            $encryptedMessage->getSessionKey()->getEncryptionKey()
        );
    }

    public function testDecryptAeadGcmMessage()
    {
        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----

wzwGGgcDCwMI6dOXhbIHAAj/tC58SD70iERXyzcmubPbn/d25fTZpAlS4kRymIUa
v/91Jt8t1VRBdXmneZ/SaQIHAwb8uUSQvLmLvcnRBsYJAmaUD3LontwhtVlrFXax
Ae0Pn/xvxtZbv9JNzQeQlm5tHoWjAFN4TLHYtqBpnvEhVaeyrWJYUxtXZR/Xd3kS
+pXjXZtAIW9ppMJI2yj/QzHxYykHOZ5v+Q==
-----END PGP MESSAGE-----
EOT;

        $encryptedMessage = OpenPGP::readEncryptedMessage($messageData);
        $decryptedMessage = $encryptedMessage->decrypt(
            passwords: [self::PASSPHRASE]
        );
        $this->assertSame(
            "Hello, world!",
            $decryptedMessage->getLiteralData()->getData()
        );
        $this->assertSame(
            hex2bin("1936fc8568980274bb900d8319360c77"),
            $encryptedMessage->getSessionKey()->getEncryptionKey()
        );
    }

    public function testDecryptMessageUsingArgon2()
    {
        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----
Comment: Encrypted using AES with 128-bit key
Comment: Session key: 01FE16BBACFD1E7B78EF3B865187374F

wycEBwScUvg8J/leUNU1RA7N/zE2AQQVnlL8rSLPP5VlQsunlO+ECxHSPgGYGKY+
YJz4u6F+DDlDBOr5NRQXt/KJIf4m4mOlKyC/uqLbpnLJZMnTq3o79GxBTdIdOzhH
XfA3pqV4mTzF
-----END PGP MESSAGE-----
EOT;

        $encryptedMessage = OpenPGP::readEncryptedMessage($messageData);
        $decryptedMessage = $encryptedMessage->decrypt(
            passwords: [self::PASSPHRASE]
        );
        $this->assertSame(
            "Hello, world!",
            $decryptedMessage->getLiteralData()->getData()
        );
        $this->assertSame(
            hex2bin("01fe16bbacfd1e7b78ef3b865187374f"),
            $encryptedMessage->getSessionKey()->getEncryptionKey()
        );

        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----
Comment: Encrypted using AES with 192-bit key
Comment: Session key: 27006DAE68E509022CE45A14E569E91001C2955...
Comment: Session key: ...AF8DFE194

wy8ECAThTKxHFTRZGKli3KNH4UP4AQQVhzLJ2va3FG8/pmpIPd/H/mdoVS5VBLLw
F9I+AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRys
LVg77Mwwfgl2n/d572WciAM=
-----END PGP MESSAGE-----
EOT;

        $encryptedMessage = OpenPGP::readEncryptedMessage($messageData);
        $decryptedMessage = $encryptedMessage->decrypt(
            passwords: [self::PASSPHRASE]
        );
        $this->assertSame(
            "Hello, world!",
            $decryptedMessage->getLiteralData()->getData()
        );
        $this->assertSame(
            hex2bin("27006dae68e509022ce45a14e569e91001c2955af8dfe194"),
            $encryptedMessage->getSessionKey()->getEncryptionKey()
        );

        $messageData = <<<EOT
-----BEGIN PGP MESSAGE-----
Comment: Encrypted using AES with 256-bit key
Comment: Session key: BBEDA55B9AAE63DAC45D4F49D89DACF4AF37FEF...
Comment: Session key: ...C13BAB2F1F8E18FB74580D8B0

wzcECQS4eJUgIG/3mcaILEJFpmJ8AQQVnZ9l7KtagdClm9UaQ/Z6M/5roklSGpGu
623YmaXezGj80j4B+Ku1sgTdJo87X1Wrup7l0wJypZls21Uwd67m9koF60eefH/K
95D1usliXOEm8ayQJQmZrjf6K6v9PWwqMQ==
-----END PGP MESSAGE-----
EOT;

        $encryptedMessage = OpenPGP::readEncryptedMessage($messageData);
        $decryptedMessage = $encryptedMessage->decrypt(
            passwords: [self::PASSPHRASE]
        );
        $this->assertSame(
            "Hello, world!",
            $decryptedMessage->getLiteralData()->getData()
        );
        $this->assertSame(
            hex2bin(
                "bbeda55b9aae63dac45d4f49d89dacf4af37fefc13bab2f1f8e18fb74580d8b0"
            ),
            $encryptedMessage->getSessionKey()->getEncryptionKey()
        );
    }
}
