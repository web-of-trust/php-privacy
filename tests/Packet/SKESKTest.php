<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Common\Config;
use OpenPGP\Packet\LiteralData;
use OpenPGP\Packet\PacketList;
use OpenPGP\Packet\SymEncryptedSessionKey;
use OpenPGP\Packet\SymEncryptedIntegrityProtectedData;
use OpenPGP\Packet\Key\SessionKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for Symmetric-Key Encrypted Session Key packet.
 */
class SKESKTest extends OpenPGPTestCase
{
    const PASSPHRASE = 'password';
    const LITERAL_TEXT = 'Hello PHP Privacy';

    public function testEncryptNullSessionKey()
    {
        $skesk = SymEncryptedSessionKey::encryptSessionKey(self::PASSPHRASE);
        $seip = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
            $skesk->getSessionKey(),
            new PacketList([LiteralData::fromText(self::LITERAL_TEXT)])
        );

        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertTrue(empty($skesk->getEncrypted()));
        $this->assertSame($skesk->getSessionKey()->getSymmetric(), $skesk->getSymmetric());
        $this->assertTrue(!empty($seip->getEncrypted()));

        $packets = PacketList::decode((new PacketList([$skesk, $seip]))->encode());
        $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
        $seip = $packets->offsetGet(1)->decryptWithSessionKey(
            $skesk->getSessionKey()
        );
        $literalData = $seip->getPacketList()->offsetGet(0);

        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    }

    public function testEncryptSessionKey()
    {
        $sessionKey = SessionKey::produceKey();
        $skesk = SymEncryptedSessionKey::encryptSessionKey(self::PASSPHRASE, $sessionKey);
        $seip = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
            $skesk->getSessionKey(),
            new PacketList([LiteralData::fromText(self::LITERAL_TEXT)])
        );

        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertTrue(!empty($skesk->getEncrypted()));
        $this->assertTrue(!empty($seip->getEncrypted()));

        $packets = PacketList::decode((new PacketList([$skesk, $seip]))->encode());
        $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
        $seip = $packets->offsetGet(1)->decryptWithSessionKey(
            $skesk->getSessionKey()
        );
        $literalData = $seip->getPacketList()->offsetGet(0);

        $this->assertTrue($skesk instanceof SymEncryptedSessionKey);
        $this->assertTrue($seip instanceof SymEncryptedIntegrityProtectedData);
        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
        $this->assertEquals($sessionKey, $skesk->getSessionKey());
    }

    // public function testAeadEncryptSessionKey()
    // {
    //     Config::setAeadProtect(true);

    //     $sessionKey = SessionKey::produceKey();
    //     $skesk = SymEncryptedSessionKey::encryptSessionKey(self::PASSPHRASE, $sessionKey);
    //     $aead = AeadEncryptedData::encryptPacketsWithSessionKey(
    //         $skesk->getSessionKey(),
    //         new PacketList([LiteralData::fromText(self::LITERAL_TEXT)])
    //     );

    //     $this->assertSame(SymEncryptedSessionKey::VERSION_5, $skesk->getVersion());
    //     $this->assertTrue(!empty($skesk->getEncrypted()));
    //     $this->assertTrue(!empty($aead->getEncrypted()));

    //     $packets = PacketList::decode((new PacketList([$skesk, $aead]))->encode());
    //     $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
    //     $aead = $packets->offsetGet(1)->decryptWithSessionKey(
    //         $skesk->getSessionKey()
    //     );
    //     $literalData = $aead->getPacketList()->offsetGet(0);

    //     $this->assertTrue($skesk instanceof SymEncryptedSessionKey);
    //     $this->assertTrue($aead instanceof AeadEncryptedData);
    //     $this->assertSame(SymEncryptedSessionKey::VERSION_5, $skesk->getVersion());
    //     $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    //     $this->assertEquals($sessionKey, $skesk->getSessionKey());

    //     Config::setAeadProtect(false);
    // }
}
