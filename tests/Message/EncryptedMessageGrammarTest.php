<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\Common\Config;
use OpenPGP\OpenPGP;
use OpenPGP\Packet\{LiteralData, Marker, PacketList, Padding};
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the grammar of encrypted messages
 * (RFC 9580, section 10.3).
 */
class EncryptedMessageGrammarTest extends OpenPGPTestCase
{
    /**
     * The packets of a message encrypted with a password:
     * one encrypted session key packet and one encrypted data packet.
     */
    private static function packets(): array
    {
        return OpenPGP::encrypt(
            OpenPGP::createLiteralMessage("Hello"),
            passwords: ["password"]
        )->getPacketList()->getPackets();
    }

    private static function read(array $packets)
    {
        return OpenPGP::readEncryptedMessage(
            (new PacketList($packets))->encode(),
            false
        );
    }

    public function testWellFormedMessagesAreRead()
    {
        [$esk, $data] = self::packets();
        foreach (
            [
                [$esk, $data],
                [new Marker(), $esk, $data],
                [$esk, $data, Padding::createPadding(16)],
                [Padding::createPadding(16), $esk, $data],
            ]
            as $packets
        ) {
            $this->assertSame(
                "Hello",
                self::read($packets)
                    ->decrypt(passwords: ["password"])
                    ->getLiteralData()
                    ->getData()
            );
        }
    }

    public function testPacketsOutOfPlaceAreRejected()
    {
        [$esk, $data] = self::packets();
        $literal = LiteralData::fromText("Hello");
        foreach (
            [
                "a literal data packet after the encrypted data" => [
                    $esk,
                    $data,
                    $literal,
                ],
                "two encrypted data packets" => [$esk, $data, $data],
                "a session key packet after the encrypted data" => [
                    $data,
                    $esk,
                ],
                "a literal data packet before the encrypted data" => [
                    $literal,
                    $esk,
                    $data,
                ],
            ]
            as $case => $packets
        ) {
            $error = "";
            try {
                self::read($packets);
            } catch (\RuntimeException $e) {
                $error = $e->getMessage();
            }
            $this->assertStringContainsString(
                "section 10.3",
                $error,
                "Read a message with {$case}."
            );
        }
    }

    public function testCheckCanBeSwitchedOff()
    {
        [$esk, $data] = self::packets();
        $packets = [$esk, $data, LiteralData::fromText("Hello")];
        $this->assertTrue(Config::checkMessageGrammar());
        Config::setCheckMessageGrammar(false);
        try {
            $message = self::read($packets);
        } finally {
            Config::setCheckMessageGrammar(true);
        }
        $this->assertSame(
            "Hello",
            $message
                ->decrypt(passwords: ["password"])
                ->getLiteralData()
                ->getData()
        );
    }
}
