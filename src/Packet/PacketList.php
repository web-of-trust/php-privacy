<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\PacketTag;
use OpenPGP\Type\{
    PacketInterface,
    PacketListInterface,
};

/**
 * Packet list class
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PacketList implements PacketListInterface
{
    /**
     * Packet list
     *
     * @var array $packets
     */
    private readonly array $packets;

    /**
     * Packet tag support partial body length
     */
    const PARTIAL_SUPPORTING = [
        PacketTag::AeadEncryptedData,
        PacketTag::CompressedData,
        PacketTag::LiteralData,
        PacketTag::SymEncryptedData,
        PacketTag::SymEncryptedIntegrityProtectedData,
    ];

    const PARTIAL_CHUNK_SIZE = 1024;
    const PARTIAL_MIN_SIZE   = 512;

    /**
     * Constructor
     *
     * @param array $packets
     * @return self
     */
    public function __construct(array $packets = [])
    {
        $this->packets = array_values(array_filter(
            $packets,
            static fn ($packet) => $packet instanceof PacketInterface
        ));
    }

    /**
     * Decode packets from bytes
     * 
     * @param string $bytes
     * @return self
     */
    public static function decode(string $bytes): self
    {
        $packets = [];
        $offset = 0;
        $len = strlen($bytes);
        while ($offset < $len) {
            $reader = PacketReader::read($bytes, $offset);
            $offset = $reader->getOffset();

            switch ($reader->getPacketTag()) {
                case PacketTag::PublicKeyEncryptedSessionKey:
                    $packets[] = PublicKeyEncryptedSessionKey::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::Signature:
                    $packets[] = Signature::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::SymEncryptedSessionKey:
                    $packets[] = SymEncryptedSessionKey::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::OnePassSignature:
                    $packets[] = OnePassSignature::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::SecretKey:
                    $packets[] = SecretKey::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::PublicKey:
                    $packets[] = PublicKey::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::SecretSubkey:
                    $packets[] = SecretSubkey::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::CompressedData:
                    $packets[] = CompressedData::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::SymEncryptedData:
                    $packets[] = SymEncryptedData::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::Marker:
                    $packets[] = new Marker();
                    break;
                case PacketTag::LiteralData:
                    $packets[] = LiteralData::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::Trust:
                    $packets[] = Trust::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::UserID:
                    $packets[] = UserID::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::PublicSubkey:
                    $packets[] = PublicSubkey::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::UserAttribute:
                    $packets[] = UserAttribute::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::SymEncryptedIntegrityProtectedData:
                    $packets[] = SymEncryptedIntegrityProtectedData::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::AeadEncryptedData:
                    $packets[] = AeadEncryptedData::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::Padding:
                    $packets[] = Padding::fromBytes(
                        $reader->getData()
                    );
                    break;
                default:
                    break;
            }
        }
        return new PacketList($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function getPackets(): array
    {
        return $this->packets;
    }

    /**
     * {@inheritdoc}
     */
    public function getIterator(): \Iterator
    {
        return new \ArrayIterator($this->packets);
    }

    /**
     * {@inheritdoc}
     */
    public function count(): int
    {
        return count($this->packets);
    }

    /**
     * {@inheritdoc}
     */
    public function whereTag(PacketTag $tag): self
    {
        $packets = array_values(array_filter(
            $this->packets,
            static fn ($packet) => $packet->getTag() === $tag
        ));
        return new self($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function whereType(string $type): self
    {
        $packets = array_values(array_filter(
            $this->packets,
            static fn ($packet) => $packet instanceof $type
        ));
        return new self($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function slice(int $offset, ?int $length = null): self
    {
        return new self(array_slice($this->packets, $offset, $length));
    }

    /**
     * {@inheritdoc}
     */
    public function indexOfTags(...$tags): array
    {
        $indexes = [];
        foreach ($this->packets as $index => $packet) {
            if (in_array($packet->getTag(), $tags, true)) {
                $indexes[] = $index;
            }
        }
        return $indexes;
    }

    /**
     * {@inheritdoc}
     */
    public function offsetExists(mixed $offset): bool
    {
        return isset($this->packets[(int) $offset]);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetGet(mixed $offset): mixed
    {
        return $this->packets[(int) $offset];
    }

    /**
     * {@inheritdoc}
     */
    public function offsetSet(mixed $offset, mixed $value): void
    {
    }

    /**
     * {@inheritdoc}
     */
    public function offsetUnset(mixed $offset): void
    {
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode(array_map(
            static fn ($packet): string => self::encodePacket($packet),
            $this->packets
        ));
    }

    private static function encodePacket(PacketInterface $packet): string
    {
        if (in_array($packet->getTag(), self::PARTIAL_SUPPORTING, true)) {
            $buffer = '';
            $partialData = [];
            $chunks = str_split($packet->toBytes(), self::PARTIAL_CHUNK_SIZE);
            foreach ($chunks as $chunk) {
                $buffer .= $chunk;
                $bufferLength = strlen($buffer);
                if ($bufferLength >= self::PARTIAL_MIN_SIZE) {
                    $powerOf2 = min(log($bufferLength) / M_LN2 | 0, 30);
                    $chunkSize = 1 << $powerOf2;
                    $partialData[] = implode([
                        self::partialLength($powerOf2),
                        substr($buffer, 0, $chunkSize),
                    ]);
                    $buffer = substr($buffer, $chunkSize);
                }
            }
            if (!empty($buffer)) {
                $partialData[] = implode([
                    AbstractPacket::simpleLength(strlen($buffer)),
                    $buffer,
                ]);
            }

            return implode([
                chr(0xc0 | $packet->getTag()->value),
                ...$partialData,
            ]);
        }
        else {
            return $packet->encode();
        }
    }

    private static function partialLength(int $power): string
    {
        if ($power < 0 || $power > 30) {
            throw new \UnexpectedValueException(
                'Partial length power must be between 1 and 30'
            );
        }
        return chr(224 + $power);
    }
}
