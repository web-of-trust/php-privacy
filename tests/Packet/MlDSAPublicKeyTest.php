<?php declare(strict_types=1);

use OpenPGP\Enum\KeyAlgorithm;
use OpenPGP\Packet\PublicKey;
use OpenPGP\Tests\OpenPGPTestCase;

if (extension_loaded('pqcrypto')) {
    /**
     * Testcase class for MlDSA public key packet.
     */
    class MlDSAPublicKeyTest extends OpenPGPTestCase
    {
        public function testMlDSA65PublicKey()
        {
            $data = <<<EOT
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
EOT;
            $publicKey = PublicKey::fromBytes(base64_decode($data));
            $this->assertSame(
                "a3e2e14b6a493ff930fb27321f125e9a6880338be9fb7da3ae065ea65793242f",
                $publicKey->getFingerprint(true)
            );
            $this->assertSame(KeyAlgorithm::MlDsa65Ed25519, $publicKey->getKeyAlgorithm());
            $this->assertSame(6, $publicKey->getVersion());
        }

        public function testMlDSA87PublicKey()
        {
            $data = <<<EOT
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
EOT;
            $publicKey = PublicKey::fromBytes(base64_decode($data));
            $this->assertSame(
                "0d7a8be1410cd68eed4845ab487b4b4cfaecd8ebad1a1166a84230499200ee20",
                $publicKey->getFingerprint(true)
            );
            $this->assertSame(KeyAlgorithm::MlDsa87Ed448, $publicKey->getKeyAlgorithm());
            $this->assertSame(6, $publicKey->getVersion());
        }
    }
}
