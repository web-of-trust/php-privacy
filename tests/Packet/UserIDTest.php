<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use phpseclib3\Crypt\Random;
use OpenPGP\Packet\ImageUserAttribute;
use OpenPGP\Packet\UserAttribute;
use OpenPGP\Packet\UserAttributeSubpacket;
use OpenPGP\Packet\UserID;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for public key packet.
 */
class UserIDTest extends OpenPGPTestCase
{
    public function testUserID()
    {
        $name = $this->faker->unique()->name();
        $email = $this->faker->unique()->safeEmail();
        $comment = $this->faker->unique()->sentence(3);

        $userID = new UserID(implode(' ', [
            $name,
            "($comment)",
            "<$email>",
        ]));
        $this->assertSame($name, $userID->getName());
        $this->assertSame($email, $userID->getEmail());
        $this->assertSame($comment, $userID->getComment());

        $clone = UserID::fromBytes($userID->toBytes());
        $this->assertSame($name, $clone->getName());
        $this->assertSame($email, $clone->getEmail());
        $this->assertSame($comment, $clone->getComment());
    }

    public function testUserAttribute()
    {
        $imageData = Random::string(100);
        $subpacketData = Random::string(100);
        $subpacketType = $this->faker->randomDigit();

        $imageAttr = ImageUserAttribute::fromImageData($imageData);
        $userAttr = new UserAttributeSubpacket($subpacketType, $subpacketData);

        $packet = new UserAttribute([$imageAttr, $userAttr]);
        $this->assertSame($imageAttr, $packet->getAttributes()[0]);
        $this->assertSame($userAttr, $packet->getAttributes()[1]);

        $clone = UserAttribute::fromBytes($packet->toBytes());
        $this->assertEquals($imageAttr, $clone->getAttributes()[0]);
        $this->assertEquals($userAttr, $clone->getAttributes()[1]);
    }
}
