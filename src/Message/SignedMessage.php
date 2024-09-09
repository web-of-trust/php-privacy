<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Message;

use DateTimeInterface;
use OpenPGP\Common\Armor;
use OpenPGP\Enum\ArmorType;
use OpenPGP\Packet\PacketList;
use OpenPGP\Type\{
    SignatureInterface,
    SignedMessageInterface,
};

/**
 * OpenPGP signed message class
 *
 * Class that represents an OpenPGP cleartext signed message.
 * See RFC 9580, section 7.
 * 
 * @package  OpenPGP
 * @category Message
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SignedMessage extends CleartextMessage implements SignedMessageInterface
{
    /**
     * Constructor
     *
     * @param string $text
     * @param SignatureInterface $signature
     * @return self
     */
    public function __construct(
        string $text,
        private readonly SignatureInterface $signature
    )
    {
        parent::__construct($text);
    }

    /**
     * Read signed message from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::SignedMessage) {
            throw new \UnexpectedValueException(
                'Armored text not of signed message type.'
            );
        }
        return new self(
            $armor->getText(),
            new Signature(
                PacketList::decode($armor->getData())
            )
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getSignature(): SignatureInterface
    {
        return $this->signature;
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        $hashes = array_map(
            static fn ($packet) => strtoupper(
                $packet->getHashAlgorithm()->name
            ),
            $this->signature->getPackets()
        );
        return Armor::encode(
            ArmorType::SignedMessage,
            $this->signature->getPacketList()->encode(),
            $this->getText(),
            implode(',', $hashes)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        array $verificationKeys, ?DateTimeInterface $time = null
    ): array
    {
        return $this->signature->verifyCleartext(
            $verificationKeys, $this, $time
        );
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return $this->armor();
    }
}
