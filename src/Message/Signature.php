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

use OpenPGP\Enum\ArmorType;
use OpenPGP\Type\{
    ArmorableInterface,
    PacketContainerInterface,
    PacketListInterface,
    SignatureInterface,
    SignaturePacketInterface
};

/**
 * Signature class
 * Class that represents an OpenPGP signature.
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class Signature implements ArmorableInterface, PacketContainerInterface, SignatureInterface
{
    private readonly array $signaturePackets;

    /**
     * Constructor
     *
     * @param array $signaturePackets
     * @return self
     */
    public function __construct(
        array $signaturePackets
    )
    {
        $this->signaturePackets = array_filter(
            $signaturePackets,
            static fn ($packet) => $packet instanceof SignaturePacketInterface
        );
    }

    /**
     * Reads signature from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::Signature) {
            throw new \UnexpectedValueException(
                'Armored text not of signature type'
            );
        }
        return new self(
            PacketList::decode($armor->getData())->toArray()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getSignaturePackets(): array
    {
        return $this->signaturePackets;
    }

    /**
     * {@inheritdoc}
     */
    public function getSigningKeyIDs(): array
    {
        return array_map(
            static fn ($packet) => $packet->getIssuerKeyID()->getKeyID(),
            $this->signaturePackets
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
        return new PacketList($this->signaturePackets);
    }
}
