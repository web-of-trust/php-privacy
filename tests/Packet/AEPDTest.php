<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\{
    AeadAlgorithm,
    SymmetricAlgorithm,
};
use OpenPGP\Packet\AeadEncryptedData;
use OpenPGP\Packet\LiteralData;
use OpenPGP\Packet\PacketList;
use OpenPGP\Packet\Key\SessionKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for AEPD packet.
 */
class AEPDTest extends OpenPGPTestCase
{
    const LITERAL_TEXT = "Hello, world!\n";

    public function testAeadEaxDecrypt()
    {
        $key = hex2bin('86f1efb86952329f24acd3bfd0e5346d');
        $iv = hex2bin('b732379f73c4928de25facfe6517ec10');
        $bytes = hex2bin('0107010eb732379f73c4928de25facfe6517ec105dc11a81dc0cb8a2f6f3d90016384a56fc821ae11ae8dbcb49862655dea88d06a81486801b0ff387bd2eab013de1259586906eab2476');

        $aepd = AeadEncryptedData::fromBytes($bytes);
        $this->assertEquals($aepd->getSymmetric(), SymmetricAlgorithm::Aes128);
        $this->assertEquals($aepd->getAead(), AeadAlgorithm::Eax);
        $this->assertSame($aepd->getChunkSize(), 14);
        $this->assertSame($aepd->getIV(), $iv);

        $aepd = $aepd->decrypt($key);
        $literalData = $aepd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, $literalData->getData());
    }

    public function testAeadOcbDecrypt()
    {
        $key = hex2bin('d1f01ba30e130aa7d2582c16e050ae44');
        $iv = hex2bin('5ed2bc1e470abe8f1d644c7a6c8a56');
        $bytes = hex2bin('0107020e5ed2bc1e470abe8f1d644c7a6c8a567b0f7701196611a154ba9c2574cd056284a8ef68035c623d93cc708a43211bb6eaf2b27f7c18d571bcd83b20add3a08b73af15b9a098');

        $aepd = AeadEncryptedData::fromBytes($bytes);
        $this->assertEquals($aepd->getSymmetric(), SymmetricAlgorithm::Aes128);
        $this->assertEquals($aepd->getAead(), AeadAlgorithm::Ocb);
        $this->assertSame($aepd->getChunkSize(), 14);
        $this->assertSame($aepd->getIV(), $iv);

        $aepd = $aepd->decrypt($key);
        $literalData = $aepd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, $literalData->getData());
    }

    public function testAeadEncrypt()
    {
        $sessionKey = SessionKey::produceKey();
        $aepd = AeadEncryptedData::encryptPacketsWithSessionKey(
            $sessionKey,
            new PacketList([LiteralData::fromText(self::LITERAL_TEXT)])
        );
        $this->assertEquals($aepd->getSymmetric(), SymmetricAlgorithm::Aes128);
        $this->assertEquals($aepd->getAead(), AeadAlgorithm::Gcm);
        $this->assertTrue(!empty($aepd->getEncrypted()));

        $aepd = $aepd->decrypt($sessionKey->getEncryptionKey());
        $literalData = $aepd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, $literalData->getData());
    }
}
