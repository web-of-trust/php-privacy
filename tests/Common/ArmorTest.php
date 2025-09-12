<?php declare(strict_types=1);

namespace OpenPGP\Tests\Common;

use phpseclib3\Crypt\Random;
use OpenPGP\Tests\OpenPGPTestCase;
use OpenPGP\Common\Armor;
use OpenPGP\Enum\ArmorType;
use OpenPGP\Enum\HashAlgorithm;

/**
 * Testcase class for Armor test.
 */
class ArmorTest extends OpenPGPTestCase
{
    public function testSignedMessage()
    {
        $data = Random::string(100);
        $text = $this->faker->sentence(100);
        $hashAlgo = $this->faker->randomElement(HashAlgorithm::cases())->name;
        $armored = Armor::encode(ArmorType::SignedMessage, $data, $text, [
            $hashAlgo,
        ]);

        preg_match("/BEGIN PGP SIGNED MESSAGE/", $armored, $matches);
        preg_match("/BEGIN PGP SIGNATURE/", $armored, $beginMatches);
        preg_match("/END PGP SIGNATURE/", $armored, $endMatches);
        preg_match("/Hash: $hashAlgo/", $armored, $hashMatches);

        $this->assertTrue(!empty($matches));
        $this->assertTrue(!empty($beginMatches));
        $this->assertTrue(!empty($endMatches));

        $armor = Armor::decode($armored);
        $this->assertSame(ArmorType::SignedMessage, $armor->getType());
        $this->assertSame($data, $armor->getData());
        $this->assertSame($text, $armor->getText());
    }

    public function testMessage()
    {
        $data = Random::string(100);
        $armored = Armor::encode(ArmorType::Message, $data);

        preg_match("/BEGIN PGP MESSAGE/", $armored, $beginMatches);
        preg_match("/END PGP MESSAGE/", $armored, $endMatches);
        $this->assertTrue(!empty($beginMatches));
        $this->assertTrue(!empty($endMatches));

        $armor = Armor::decode($armored);
        $this->assertSame(ArmorType::Message, $armor->getType());
        $this->assertSame($data, $armor->getData());
    }

    public function testPublicKey()
    {
        $data = Random::string(100);
        $armored = Armor::encode(ArmorType::PublicKey, $data);

        preg_match("/BEGIN PGP PUBLIC KEY BLOCK/", $armored, $beginMatches);
        preg_match("/END PGP PUBLIC KEY BLOCK/", $armored, $endMatches);
        $this->assertTrue(!empty($beginMatches));
        $this->assertTrue(!empty($endMatches));

        $armor = Armor::decode($armored);
        $this->assertSame(ArmorType::PublicKey, $armor->getType());
        $this->assertSame($data, $armor->getData());
    }

    public function testPrivateKey()
    {
        $data = Random::string(100);
        $armored = Armor::encode(ArmorType::PrivateKey, $data);

        preg_match("/BEGIN PGP PRIVATE KEY BLOCK/", $armored, $beginMatches);
        preg_match("/END PGP PRIVATE KEY BLOCK/", $armored, $endMatches);
        $this->assertTrue(!empty($beginMatches));
        $this->assertTrue(!empty($endMatches));

        $armor = Armor::decode($armored);
        $this->assertSame(ArmorType::PrivateKey, $armor->getType());
        $this->assertSame($data, $armor->getData());
    }

    public function testSignature()
    {
        $data = Random::string(100);
        $armored = Armor::encode(ArmorType::Signature, $data);

        preg_match("/BEGIN PGP SIGNATURE/", $armored, $beginMatches);
        preg_match("/END PGP SIGNATURE/", $armored, $endMatches);
        $this->assertTrue(!empty($beginMatches));
        $this->assertTrue(!empty($endMatches));

        $armor = Armor::decode($armored);
        $this->assertSame(ArmorType::Signature, $armor->getType());
        $this->assertSame($data, $armor->getData());
    }
}
