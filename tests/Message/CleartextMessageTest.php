<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\Key\{PrivateKey, PublicKey};
use OpenPGP\Message\CleartextMessage;
use OpenPGP\Packet\LiteralData;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for cleartext message.
 */
class CleartextMessageTest extends OpenPGPTestCase
{
    const LITERAL_TEXT = 'Hello PHP PG';
    const PASSPHRASE = 'password'; 

    public function testSignRsaCleartextMessage()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/RsaPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/RsaPublicKey.asc')
        );
        $message = new CleartextMessage(self::LITERAL_TEXT);

        $signedMessage = $message->sign([$privateKey]);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('184d0dc4f5c532b2', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());

        $signature = $message->signDetached([$privateKey]);
        $verification = $signature->verify([$publicKey], LiteralData::fromText(self::LITERAL_TEXT))[0];
        $this->assertSame('184d0dc4f5c532b2', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testSignDsaCleartextMessage()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/DsaPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/DsaPublicKey.asc')
        );
        $message = new CleartextMessage(self::LITERAL_TEXT);

        $signedMessage = $message->sign([$privateKey]);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('e3b11d642248a092', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());

        $signature = $message->signDetached([$privateKey]);
        $verification = $signature->verify([$publicKey], LiteralData::fromText(self::LITERAL_TEXT))[0];
        $this->assertSame('e3b11d642248a092', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testSignEcP384CleartextMessage()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcP384PrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcP384PublicKey.asc')
        );
        $message = new CleartextMessage(self::LITERAL_TEXT);

        $signedMessage = $message->sign([$privateKey]);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('b202d9e2eada440c', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());

        $signature = $message->signDetached([$privateKey]);
        $verification = $signature->verify([$publicKey], LiteralData::fromText(self::LITERAL_TEXT))[0];
        $this->assertSame('b202d9e2eada440c', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testSignEcBrainpoolCleartextMessage()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPublicKey.asc')
        );
        $message = new CleartextMessage(self::LITERAL_TEXT);

        $signedMessage = $message->sign([$privateKey]);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('1cbcd043db44c5d6', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());

        $signature = $message->signDetached([$privateKey]);
        $verification = $signature->verify([$publicKey], LiteralData::fromText(self::LITERAL_TEXT))[0];
        $this->assertSame('1cbcd043db44c5d6', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }

    public function testSignEcCurve25519CleartextMessage()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PublicKey.asc')
        );
        $message = new CleartextMessage(self::LITERAL_TEXT);

        $signedMessage = $message->sign([$privateKey]);
        $verification = $signedMessage->verify([$publicKey])[0];
        $this->assertSame('bdff135160c56a0b', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());

        $signature = $message->signDetached([$privateKey]);
        $verification = $signature->verify([$publicKey], LiteralData::fromText(self::LITERAL_TEXT))[0];
        $this->assertSame('bdff135160c56a0b', $verification->getKeyID(true));
        $this->assertTrue($verification->isVerified());
    }
}
