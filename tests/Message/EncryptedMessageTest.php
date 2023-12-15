<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\Key\{PrivateKey, PublicKey};
use OpenPGP\Message\EncryptedMessage;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OpenPGP literal message.
 */
class EncryptedMessageTest extends OpenPGPTestCase
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


    public function testDecryptEncryptedMessage()
    {
        $encryptedMessage = EncryptedMessage::fromArmored(self::$encryptedMessageData);

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

    public function testDecryptAeadMessage()
    {
        $encryptedMessageData = <<<EOT
-----BEGIN PGP MESSAGE-----

jD0FBwIDCPTU9TrcG/ef/xFWqji4GJrUyUl69Pv5jAx2Kqji9g4nBGu5RXlYoY/8
cTHw+kww2UtrXVkeUDQI1EwBBwIQtSJxPQCq1Mg7/Ashm2BQxiCRO1DtO6TN/+sy
58ZOoB5PVTW8IcABVZi/8mtZtqY02rYfTcXYiyVQP9Qx0gnqM1hCCQp/tZYX
=id4U
-----END PGP MESSAGE-----
EOT;

        $encryptedMessage = EncryptedMessage::fromArmored($encryptedMessageData);
        $decryptedMessage = $encryptedMessage->decrypt(passwords: [self::PASSPHRASE]);
        $this->assertSame(self::LITERAL_DATA, $decryptedMessage->getLiteralData()->getData());
    }
}
