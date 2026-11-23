<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\{AeadAlgorithm, SymmetricAlgorithm};
use OpenPGP\Packet\PacketList;
use OpenPGP\Packet\SymEncryptedIntegrityProtectedData;
use OpenPGP\Packet\Key\SessionKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for SEIPD packet.
 */
class SEIPDTest extends OpenPGPTestCase
{
    public function testAeadEncryptEmptyData()
    {
        // RFC 9580, section 5.13.2: one or more chunks, then the final tag.
        // Empty data gives one empty chunk, so two authentication tags.
        foreach (AeadAlgorithm::cases() as $aead) {
            $sessionKey = SessionKey::produceKey(
                SymmetricAlgorithm::Aes256
            );
            $seipd = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
                $sessionKey,
                new PacketList([]),
                $aead
            );
            $this->assertSame(
                2 * $aead->tagLength(),
                strlen($seipd->getEncrypted())
            );

            $seipd = SymEncryptedIntegrityProtectedData::fromBytes(
                $seipd->toBytes()
            )->decrypt($sessionKey->getEncryptionKey());
            $this->assertCount(0, $seipd->getPacketList());
        }
    }
}
