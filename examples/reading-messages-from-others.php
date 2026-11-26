<?php declare(strict_types=1);

require_once dirname(__DIR__) . "/vendor/autoload.php";

use OpenPGP\OpenPGP;
use OpenPGP\Common\Config;
use OpenPGP\Enum\CompressionAlgorithm;
use OpenPGP\Message\{EncryptedMessage, LiteralMessage};
use OpenPGP\Packet\{CompressedData, LiteralData, PacketList};

$password = "correct horse battery staple";

// Limits for messages from others, set once at start-up.
Config::setMaxDecompressedSize(1024 * 1024); // 1 MiB
Config::setMaxCompressionNesting(1);
Config::setCheckMessageGrammar(true);

/**
 * Read and decrypt a message, and turn a broken or hostile message
 * into a short reason instead of an uncaught exception.
 */
function readMessage(string $armored, string $password): string
{
    try {
        $message = OpenPGP::readEncryptedMessage($armored);
        $literalMessage = OpenPGP::decrypt($message, passwords: [$password]);
        return "read " . strlen(
            $literalMessage->getLiteralData()->getData()
        ) . " octets";
    } catch (\RuntimeException $e) {
        // Limits, grammar, wrong password, failed integrity check.
        // The first line of the message names the reason.
        return "refused: " . explode(PHP_EOL, $e->getMessage())[0];
    } catch (\Throwable $e) {
        // Other malformed input.
        return "refused: malformed message";
    }
}

echo "1. A small compressed message" . PHP_EOL;
$message = OpenPGP::encrypt(
    OpenPGP::createLiteralMessage(str_repeat("Hello, PHP Privacy! ", 100)),
    passwords: [$password],
    compression: CompressionAlgorithm::Zlib,
);
echo "   " . readMessage($message->armor(), $password) . PHP_EOL;

echo "2. 8 MiB that compress to a few kilobytes" . PHP_EOL;
$message = OpenPGP::encrypt(
    OpenPGP::createLiteralMessage(str_repeat("A", 8 * 1024 * 1024)),
    passwords: [$password],
    compression: CompressionAlgorithm::Zlib,
);
echo "   armored size: " . strlen($message->armor()) . " octets" . PHP_EOL;
echo "   " . readMessage($message->armor(), $password) . PHP_EOL;

echo "3. A compressed packet inside a compressed packet" . PHP_EOL;
$nested = CompressedData::fromPackets(
    [
        CompressedData::fromPackets(
            [LiteralData::fromText("Hello, PHP Privacy!")],
            CompressionAlgorithm::Zip,
        ),
    ],
    CompressionAlgorithm::Zip,
);
$message = (new LiteralMessage(new PacketList([$nested])))->encrypt(
    passwords: [$password],
);
echo "   " . readMessage($message->armor(), $password) . PHP_EOL;

echo "4. A literal data packet after the encrypted data" . PHP_EOL;
$message = OpenPGP::encrypt(
    OpenPGP::createLiteralMessage("Hello, PHP Privacy!"),
    passwords: [$password],
);
$packets = new PacketList([
    ...$message->getPacketList()->getPackets(),
    LiteralData::fromText("Read me instead."),
]);
echo "   " . readMessage(
    (new EncryptedMessage($packets))->armor(),
    $password,
) . PHP_EOL;

echo "5. The wrong password" . PHP_EOL;
$message = OpenPGP::encrypt(
    OpenPGP::createLiteralMessage("Hello, PHP Privacy!"),
    passwords: [$password],
);
echo "   " . readMessage($message->armor(), "wrong password") . PHP_EOL;

echo "6. Not a message at all" . PHP_EOL;
echo "   " . readMessage("Hello, PHP Privacy!", $password) . PHP_EOL;
