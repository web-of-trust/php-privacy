<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
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
                case PacketTag::ModificationDetectionCode:
                    $packets[] = ModificationDetectionCode::fromBytes(
                        $reader->getData()
                    );
                    break;
                case PacketTag::AeadEncryptedData:
                    $packets[] = AeadEncryptedData::fromBytes(
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
    public function encode(): string
    {
        return implode(
            array_map(static fn ($packet) => $packet->encode(), $this->packets)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function whereTag(PacketTag $tag): self
    {
        $packets = array_filter(
            $this->packets,
            static fn ($packet) => $packet->getTag() === $tag
        );
        return new self($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function whereType(string $type): self
    {
        $packets = array_filter(
            $this->packets,
            static fn ($packet) => get_class($packet) === $type
        );
        return new self($packets);
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
}
