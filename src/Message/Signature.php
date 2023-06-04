<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Message;

use DateTimeInterface;
use OpenPGP\Common\{
    Armor,
    Config,
};
use OpenPGP\Enum\ArmorType;
use OpenPGP\Packet\{
    LiteralData,
    PacketList,
};
use OpenPGP\Type\{
    CleartextMessageInterface,
    KeyInterface,
    LiteralDataInterface,
    PacketListInterface,
    SignatureInterface,
    SignaturePacketInterface,
};

/**
 * Signature class
 * Class that represents a detacted OpenPGP signature.
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class Signature implements SignatureInterface
{
    private readonly array $packets;

    /**
     * Constructor
     *
     * @param array $packets
     * @return self
     */
    public function __construct(
        array $packets,
    )
    {
        $this->packets = array_filter(
            $packets,
            static fn ($packet) => $packet instanceof SignaturePacketInterface
        );
    }

    /**
     * Read signature from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::Signature) {
            throw new \UnexpectedValueException(
                'Armored text not of signature type.'
            );
        }
        return new self(
            PacketList::decode($armor->getData())->getPackets()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getSigningKeyIDs(bool $toHex = false): array
    {
        return array_map(
            static fn ($packet) => $packet->getIssuerKeyID($toHex),
            $this->packets
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        array $verificationKeys,
        LiteralDataInterface $literalData,
        ?DateTimeInterface $time = null
    ): array
    {
        $verificationKeys = array_filter(
            $verificationKeys,
            static fn ($key) => $key instanceof KeyInterface
        );
        if (empty($verificationKeys)) {
            Config::getLogger()->debug('No verification keys provided.');
        }
        $verifications = [];
        foreach ($this->packets as $packet) {
            foreach ($verificationKeys as $key) {
                try {
                    $keyPacket = $key->toPublic()->getSigningKeyPacket(
                        $packet->getIssuerKeyID()
                    );
                    $verifications[] = new Verification(
                        $keyPacket->getKeyID(),
                        $packet,
                        $packet->verify(
                            $keyPacket,
                            $literalData->getSignBytes(),
                            $time
                        )
                    );
                }
                catch (\Throwable $e) {
                    Config::getLogger()->error($e->getMessage());
                }
            }
        }
        return $verifications;
    }

    /**
     * {@inheritdoc}
     */
    public function verifyCleartext(
        array $verificationKeys,
        CleartextMessageInterface $cleartext,
        ?DateTimeInterface $time = null
    ): array
    {
        return $this->verify(
            $verificationKeys,
            LiteralData::fromText($cleartext->getText()),
            $time
        );
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        return Armor::encode(
            ArmorType::Signature,
            $this->toPacketList()->encode()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toPacketList(): PacketListInterface
    {
        return new PacketList($this->packets);
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
    public function __toString(): string
    {
        return $this->armor();
    }
}
