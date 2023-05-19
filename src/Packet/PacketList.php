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
use OpenPGP\Type\{PacketInterface, PacketListInterface};

/**
 * Packet list class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class PacketList implements PacketListInterface
{
    private readonly \ArrayIterator $packets;

    /**
     * Constructor
     *
     * @param array $packets
     * @return self
     */
    public function __construct(array $packets = [])
    {
        $this->packets = new \ArrayIterator(array_filter(
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
    public function getIterator(): \Iterator
    {
        return $this->packets;
    }

    /**
     * {@inheritdoc}
     */
    public function count(): int
    {
        return $this->packets->count();
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode(
            array_map(static fn ($packet) => $packet->encode(), $this->packets->getArrayCopy())
        );
    }

    /**
     * {@inheritdoc}
     */
    public function filterByTag(PacketTag $tag): self
    {
        $packets = array_filter(
            $this->packets->getArrayCopy(),
            static function ($packet) use ($tag) {
                return $packet->getTag() === $tag;
            }
        );
        return new self($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function toArray(): array
    {
        return $this->packets->getArrayCopy();
    }

    /**
     * {@inheritdoc}
     */
    public function current(): PacketInterface
    {
        return $this->packets->current();
    }

    /**
     * {@inheritdoc}
     */
    public function offsetGet($key): PacketInterface
    {
        return $this->packets->offsetGet($key);
    }
}
