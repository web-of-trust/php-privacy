<?php declare(strict_types=1);

use OpenPGP\Enum\KeyAlgorithm;
use OpenPGP\Packet\PublicKey;
use OpenPGP\Tests\OpenPGPTestCase;

if (extension_loaded('pqcrypto')) {
    /**
     * Testcase class for SlhDSA public key packet.
     */
    class SlhDSAPublicKeyTest extends OpenPGPTestCase
    {
        public function testSlhDsaShake128sPublicKey()
        {
            $data = <<<EOT
Bmd0hYAgAAAAIEDwzRzYcsydjz8NHpNAFtG8tsnpacux8VtDhep9zYa6
EOT;
            $publicKey = PublicKey::fromBytes(base64_decode($data));
            $this->assertSame(
                "eed4d13fc36c78e48276a93233339c4dd230fd5f6f5c5b82c63d5c0b5e361d92",
                $publicKey->getFingerprint(true)
            );
            $this->assertSame(KeyAlgorithm::MlDsa65Ed25519, $publicKey->getKeyAlgorithm());
            $this->assertSame(6, $publicKey->getVersion());
        }

        public function testSlhDsaShake128fPublicKey()
        {
            $data = <<<EOT
Bmd0hYAhAAAAIAD4AX00yR4RHuuMeOg1L1MaBl8qmNLOEXw3wq2VICnV
EOT;
            $publicKey = PublicKey::fromBytes(base64_decode($data));
            $this->assertSame(
                "d54e0307021169f7b88beb2b76e3aad0e114be1a8f982d74dba9ca51d03537f4",
                $publicKey->getFingerprint(true)
            );
            $this->assertSame(KeyAlgorithm::MlDsa65Ed25519, $publicKey->getKeyAlgorithm());
            $this->assertSame(6, $publicKey->getVersion());
        }

        public function testSlhDsaShake256sPublicKey()
        {
            $data = <<<EOT
Bmd0hYAiAAAAQCZvpiFm/Nt5byIwwCpCW1T1RqeSEWUwkMvEjzIoQepGEGaUnT26jjwOpYhXsY68
lRFavd9+sDPx0pwcjSW/VBU=
EOT;
            $publicKey = PublicKey::fromBytes(base64_decode($data));
            $this->assertSame(
                "72fff84863aeba67f0d1d7691173247dd427533b9d7ee76011c6f77f2ce9fa7a",
                $publicKey->getFingerprint(true)
            );
            $this->assertSame(KeyAlgorithm::MlDsa65Ed25519, $publicKey->getKeyAlgorithm());
            $this->assertSame(6, $publicKey->getVersion());
        }
    }
}

