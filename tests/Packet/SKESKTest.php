<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\{
    AeadAlgorithm,
    SymmetricAlgorithm,
};
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
    const LITERAL_TEXT = 'Hello, world!';

    public function testEncryptNullSessionKey()
    {
        $skesk = SymEncryptedSessionKey::encryptSessionKey(self::PASSPHRASE);
        $seipd = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
            $skesk->getSessionKey(),
            new PacketList([LiteralData::fromText(self::LITERAL_TEXT)])
        );

        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertTrue(empty($skesk->getEncrypted()));
        $this->assertSame($skesk->getSessionKey()->getSymmetric(), $skesk->getSymmetric());
        $this->assertTrue(!empty($seipd->getEncrypted()));

        $packets = PacketList::decode((new PacketList([$skesk, $seipd]))->encode());
        $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
        $seipd = $packets->offsetGet(1)->decryptWithSessionKey(
            $skesk->getSessionKey()
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);

        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    }

    public function testEncryptSessionKey()
    {
        $sessionKey = SessionKey::produceKey();
        $skesk = SymEncryptedSessionKey::encryptSessionKey(self::PASSPHRASE, $sessionKey);
        $seipd = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
            $skesk->getSessionKey(),
            new PacketList([LiteralData::fromText(self::LITERAL_TEXT)])
        );

        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertTrue(!empty($skesk->getEncrypted()));
        $this->assertTrue(!empty($seipd->getEncrypted()));

        $packets = PacketList::decode((new PacketList([$skesk, $seipd]))->encode());
        $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
        $seipd = $packets->offsetGet(1)->decryptWithSessionKey(
            $skesk->getSessionKey()
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);

        $this->assertTrue($skesk instanceof SymEncryptedSessionKey);
        $this->assertTrue($seipd instanceof SymEncryptedIntegrityProtectedData);
        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
        $this->assertEquals($sessionKey, $skesk->getSessionKey());
    }

    public function testAeadEaxDecryption()
    {
        $skeskData = 'Bh4HAQsDCKWuV50fxdgr/2kiT5GZk7NQb6O1mmpzz/jF78X0HFf7VOHCJoFdeCj1+SxFTrZevgCrWYbGjm58VQ==';
        $skesk = SymEncryptedSessionKey::fromBytes(base64_decode($skeskData))->decrypt(self::PASSPHRASE);

        $this->assertEquals(SymmetricAlgorithm::Aes128, $skesk->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Eax, $skesk->getAead());

        $sessionKey = $skesk->getSessionKey();
        $this->assertEquals('3881bafe985412459b86c36f98cb9a5e', bin2hex($sessionKey->getEncryptionKey()));

        $seipdData = 'AgcBBp/5DjsyGWTzpCkTyNzGYZMlAVIn77fq6qSfBMLmdBddSj0ibtavy5yprBIsFHDhHGPUwKskHGqTitSL+ZpambkLuoMl3mEEdUAlireVmpWtBR3alusVQx3+9fXiJVyngmFUbjOa';
        $seipd = SymEncryptedIntegrityProtectedData::fromBytes(base64_decode($seipdData));
        $this->assertEquals(SymmetricAlgorithm::Aes128, $seipd->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Eax, $seipd->getAead());

        $seipd = $seipd->decryptWithSessionKey(
            $sessionKey
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    }

    public function testAeadOcbDecryption()
    {
        $skeskData = 'Bh0HAgsDCFaimNL142RT/8/MXBFmTtudtCWQ19xGsHJBthLDgSz/++oA8jR7JWQRI/iHrmDU/WFOCDfYGdNs';
        $skesk = SymEncryptedSessionKey::fromBytes(base64_decode($skeskData))->decrypt(self::PASSPHRASE);
        $this->assertEquals(SymmetricAlgorithm::Aes128, $skesk->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Ocb, $skesk->getAead());

        $sessionKey = $skesk->getSessionKey();
        $this->assertEquals('28e79ab82397d3c63de24ac217d7b791', bin2hex($sessionKey->getEncryptionKey()));

        $seipdData = 'AgcCBiCmYfcx/JowMrViMyYCfjpdjbV0jr7/CwxZENCezdZB/5/ThWJ1gDW8SXVM4b8//6fa0KO4EE9RM89CpBAKg+70yhtIAaiEa/QrzafIzp1l4hLzAcvNmP3K3mlKh3rUJHMj9uhX';
        $seipd = SymEncryptedIntegrityProtectedData::fromBytes(base64_decode($seipdData));
        $this->assertEquals(SymmetricAlgorithm::Aes128, $seipd->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Ocb, $seipd->getAead());

        $seipd = $seipd->decryptWithSessionKey(
            $sessionKey
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    }

    public function testAeadGcmDecryption()
    {
        $skeskData = 'BhoHAwsDCOnTl4WyBwAI/7QufEg+9IhEV8s3Jrmz25/3duX02aQJUuJEcpiFGr//dSbfLdVUQXV5p3mf';
        $skesk = SymEncryptedSessionKey::fromBytes(base64_decode($skeskData))->decrypt(self::PASSPHRASE);
        $this->assertEquals(SymmetricAlgorithm::Aes128, $skesk->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Gcm, $skesk->getAead());

        $sessionKey = $skesk->getSessionKey();
        $this->assertEquals('1936fc8568980274bb900d8319360c77', bin2hex($sessionKey->getEncryptionKey()));

        $seipdData = 'AgcDBvy5RJC8uYu9ydEGxgkCZpQPcuie3CG1WWsVdrEB7Q+f/G/G1lu/0k3NB5CWbm0ehaMAU3hMsdi2oGme8SFVp7KtYlhTG1dlH9d3eRL6leNdm0Ahb2mkwkjbKP9DMfFjKQc5nm/5';
        $seipd = SymEncryptedIntegrityProtectedData::fromBytes(base64_decode($seipdData));
        $this->assertEquals(SymmetricAlgorithm::Aes128, $seipd->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Gcm, $seipd->getAead());

        $seipd = $seipd->decryptWithSessionKey(
            $sessionKey
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
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
