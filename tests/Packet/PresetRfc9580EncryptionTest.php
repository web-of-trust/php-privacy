<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Common\Config;
use OpenPGP\Enum\SymmetricAlgorithm;
use OpenPGP\OpenPGP;
use OpenPGP\Packet\{LiteralData, PacketList};
use OpenPGP\Packet\SymEncryptedIntegrityProtectedData;
use OpenPGP\Packet\Key\SessionKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for encryption without AEAD under the RFC 9580 preset.
 */
class PresetRfc9580EncryptionTest extends OpenPGPTestCase
{
    public function testSeipdWithoutAeadIsVersion1()
    {
        // Version 2 of the SEIPD packet is always AEAD (RFC 9580, section 5.13.2).
        Config::presetRFC9580();
        try {
            $seipd = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
                SessionKey::produceKey(SymmetricAlgorithm::Aes256),
                new PacketList([LiteralData::fromText('Hello')]),
            );
            $this->assertSame(1, $seipd->getVersion());
            $this->assertNull($seipd->getAead());
            $read = SymEncryptedIntegrityProtectedData::fromBytes($seipd->toBytes());
            $this->assertSame(1, $read->getVersion());
        } finally {
            Config::presetRFC4880();
        }
    }

    public function testEncryptWithPasswordOnly()
    {
        Config::presetRFC9580();
        try {
            $armored = OpenPGP::encrypt(
                OpenPGP::createLiteralMessage('Hello'),
                passwords: ['password'],
            )->armor();
            $message = OpenPGP::decryptMessage($armored, passwords: ['password']);
            $this->assertSame('Hello', $message->getLiteralData()->getData());
        } finally {
            Config::presetRFC4880();
        }
    }

    public function testEncryptWithPasswordAndAeadProtect()
    {
        Config::presetRFC9580();
        Config::setAeadProtect(true);
        try {
            $encrypted = OpenPGP::encrypt(
                OpenPGP::createLiteralMessage('Hello'),
                passwords: ['password'],
            );
            $this->assertSame(2, $encrypted->getEncryptedPacket()->getVersion());
            $message = OpenPGP::decryptMessage(
                $encrypted->armor(),
                passwords: ['password'],
            );
            $this->assertSame('Hello', $message->getLiteralData()->getData());
        } finally {
            Config::setAeadProtect(false);
            Config::presetRFC4880();
        }
    }
}
