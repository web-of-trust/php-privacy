<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\PacketTag;
use OpenPGP\Type\{PacketInterface, PacketListInterface};
use phpseclib3\Common\Functions\Strings;

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
        $this->packets = array_values(
            array_filter(
                $packets,
                static fn($packet) => $packet instanceof PacketInterface
            )
        );
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
        while (strlen($bytes)) {
            $reader = PacketReader::read($bytes);
            Strings::shift($bytes, $reader->getLength());
            $packets[] = match ($reader->getTag()) {
                PacketTag::PublicKeyEncryptedSessionKey
                    => PublicKeyEncryptedSessionKey::fromBytes(
                    $reader->getData()
                ),
                PacketTag::Signature => Signature::fromBytes(
                    $reader->getData()
                ),
                PacketTag::SymmetricKeyEncryptedSessionKey
                    => SymmetricKeyEncryptedSessionKey::fromBytes($reader->getData()),
                PacketTag::OnePassSignature => OnePassSignature::fromBytes(
                    $reader->getData()
                ),
                PacketTag::SecretKey => SecretKey::fromBytes(
                    $reader->getData()
                ),
                PacketTag::PublicKey => PublicKey::fromBytes(
                    $reader->getData()
                ),
                PacketTag::SecretSubkey => SecretSubkey::fromBytes(
                    $reader->getData()
                ),
                PacketTag::CompressedData => CompressedData::fromBytes(
                    $reader->getData()
                ),
                PacketTag::SymEncryptedData => SymEncryptedData::fromBytes(
                    $reader->getData()
                ),
                PacketTag::Marker => new Marker(),
                PacketTag::LiteralData => LiteralData::fromBytes(
                    $reader->getData()
                ),
                PacketTag::Trust => Trust::fromBytes($reader->getData()),
                PacketTag::UserID => UserID::fromBytes($reader->getData()),
                PacketTag::PublicSubkey => PublicSubkey::fromBytes(
                    $reader->getData()
                ),
                PacketTag::UserAttribute => UserAttribute::fromBytes(
                    $reader->getData()
                ),
                PacketTag::SymEncryptedIntegrityProtectedData
                    => SymEncryptedIntegrityProtectedData::fromBytes(
                    $reader->getData()
                ),
                PacketTag::AeadEncryptedData => AeadEncryptedData::fromBytes(
                    $reader->getData()
                ),
                PacketTag::Padding => Padding::fromBytes($reader->getData()),
                default => null,
            };
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
    public function encode(): string
    {
        return implode(
            array_map(
                static fn($packet): string => $packet->encode(),
                $this->packets
            )
        );
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
        $packets = array_values(
            array_filter(
                $this->packets,
                static fn($packet) => $packet->getTag() === $tag
            )
        );
        return new self($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function whereType(string $type): self
    {
        $packets = array_values(
            array_filter(
                $this->packets,
                static fn($packet) => $packet instanceof $type
            )
        );
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
}
