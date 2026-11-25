<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\Enum\KeyType;
use OpenPGP\OpenPGP;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the use of revoked keys.
 */
class RevokedKeyTest extends OpenPGPTestCase
{
    private static function key()
    {
        return OpenPGP::generateKey(
            ["Alice <alice@example.org>"],
            "password",
            KeyType::Ecc
        )->decrypt("password");
    }

    public function testSignatureOfRevokedKeyIsNotVerified()
    {
        $key = self::key();
        $message = OpenPGP::createLiteralMessage("Hello");
        $signature = OpenPGP::signDetached($message, [$key]);
        $public = $key->toPublic();
        $revoked = $public->revokeBy($key);
        $this->assertTrue($revoked->isRevoked());

        $before = $signature->verify([$public], $message->getLiteralData());
        $this->assertTrue($before[0]->isVerified());

        $after = $signature->verify([$revoked], $message->getLiteralData());
        foreach ($after as $verification) {
            $this->assertFalse(
                $verification->isVerified(),
                "Signature of a revoked key was verified."
            );
        }
        $this->assertNotEmpty($after);
        $this->assertSame(
            "Verification key is revoked.",
            $after[0]->getVerificationError()
        );
    }

    public function testEncryptingToRevokedKeyIsRefused()
    {
        $key = self::key();
        $message = OpenPGP::createLiteralMessage("Hello");
        $public = $key->toPublic();
        $this->assertNotEmpty(
            OpenPGP::encrypt($message, [$public])->armor()
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("is revoked");
        OpenPGP::encrypt($message, [$public->revokeBy($key)]);
    }
}
