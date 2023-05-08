<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Packet\PublicKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for Public key packet.
 */
class PublicKeyTest extends OpenPGPTestCase
{
    public function testRSAPublicKey()
    {
        $data = <<<EOT
BGRUrD4BCACe8iv48dGvqnbOuPv1DnnrasH/NZ5bbpGHW0gSOXb4p2d7VcfA6hfoyq1yEuZ2VDzJ
WpkhVnKMF1Ytj7d8mtnGsTQ6NfGrV9jRhGIxAYIgiDjzuhIejzMrTR/RAh9aARPTuEayRXoShTEg
cQfZxIQKwwU5hE4PDZFhq0h/T83eImWidUZwt3zw6jWq29nDtmtR96x+xznG0utZrHsbkxNtuLpX
YlrMl9Lcz9vbntpK45aq35P3cfg5UEjCLj1TAq6LPFnfiwbQcNkbsTRsxPqWpX4J6v5ZabJIFGyd
K14eiohYTbp7Uvr/e3yRhTirWYz4KnJwuFOsemuSjSAGi3C5ABEBAAE=
EOT;
        $publicKey = PublicKey::fromBytes(base64_decode($data));
        $this->assertSame('fc5004df9473277107eaa605184d0dc4f5c532b2', bin2hex($publicKey->getFingerprint()));
        $this->assertSame('184d0dc4f5c532b2', bin2hex($publicKey->getKeyID()));
    }
}
