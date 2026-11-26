<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\Enum\KeyType;
use OpenPGP\OpenPGP;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the use of expired keys.
 */
class ExpiredKeyTest extends OpenPGPTestCase
{
    /**
     * A key made on 2020-01-01 that is valid for one day.
     */
    private static function expiredKey()
    {
        return OpenPGP::generateKey(
            ["Alice <alice@example.org>"],
            "password",
            KeyType::Ecc,
            keyExpiry: 86400,
            time: new \DateTime("2020-01-01T00:00:00Z")
        )->decrypt("password");
    }

    public function testSignatureOfExpiredKeyIsNotVerified()
    {
        $key = self::expiredKey();
        $public = $key->toPublic();
        $this->assertSame(
            "2020-01-02",
            $public->getExpirationTime()->format("Y-m-d")
        );
        $message = OpenPGP::createLiteralMessage("Hello");

        // Made while the key was valid: verified.
        $before = OpenPGP::signDetached(
            $message,
            [$key],
            time: new \DateTime("2020-01-01T12:00:00Z")
        )->verify([$public], $message->getLiteralData());
        $this->assertNotEmpty($before);
        $this->assertTrue($before[0]->isVerified());

        // Made after the key expired: not verified.
        $after = OpenPGP::signDetached($message, [$key])->verify(
            [$public],
            $message->getLiteralData()
        );
        $this->assertNotEmpty($after);
        foreach ($after as $verification) {
            $this->assertFalse(
                $verification->isVerified(),
                "Signature made after the key expired was verified."
            );
        }
        $this->assertSame(
            "Verification key is expired.",
            $after[0]->getVerificationError()
        );
    }

    public function testEncryptingToExpiredKeyIsRefused()
    {
        $message = OpenPGP::createLiteralMessage("Hello");
        $valid = OpenPGP::generateKey(
            ["Bob <bob@example.org>"],
            "password",
            KeyType::Ecc
        )->toPublic();
        $this->assertNotEmpty(
            OpenPGP::encrypt($message, [$valid])->armor()
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("is expired");
        OpenPGP::encrypt($message, [self::expiredKey()->toPublic()]);
    }
}
