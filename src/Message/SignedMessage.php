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

use OpenPGP\Common\{Armor, Helper};
use OpenPGP\Enum\ArmorType;
use OpenPGP\Packet\LiteralData;
use OpenPGP\Type\{
    ArmorableInterface,
    KeyInterface,
    SignatureInterface,
    SignedMessageInterface,
    VerificationInterface
};

/**
 * OpenPGP signed message class
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SignedMessage extends CleartextMessage implements ArmorableInterface, SignedMessageInterface
{
    private readonly array $verifications;

    /**
     * Constructor
     *
     * @param string $text
     * @param SignatureInterface $signature
     * @param array $verifications
     * @return self
     */
    public function __construct(
        string $text,
        private readonly SignatureInterface $signature,
        array $verifications = [],
    )
    {
        parent::__construct($text);
        $this->verifications = array_filter(
            $verifications,
            static fn ($verification) => $verification instanceof VerificationInterface
        );
    }

    /**
     * Reads signed message from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::SignedMessage) {
            throw new \UnexpectedValueException(
                'Armored text not of signed message type'
            );
        }
        return new self(
            $armor->getText(),
            new Signature(
                PacketList::decode($armor->getData())->toArray()
            )
        );
    }

    /**
     * Gets signature 
     *
     * @return SignatureInterface
     */
    public function getSignature(): SignatureInterface
    {
        return $this->signature;
    }

    /**
     * Gets verifications 
     *
     * @return array
     */
    public function getVerifications(): array
    {
        return $this->verifications;
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        $hashes = array_map(
            static fn ($packet) => strtoupper($packet->getHashAlgorithm()->name),
            $this->signature->getSignaturePackets()
        );
        return Armor::encode(
            ArmorType::SignedMessage,
            $this->signature->toPacketList()->encode(),
            $this->getText(),
            implode(',', $hashes)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        array $verificationKeys, ?DateTime $time = null
    ): self
    {
        $verificationKeys = array_filter($verificationKeys, static fn ($key) => $key instanceof KeyInterface);
        if (empty($verificationKeys)) {
            throw new \InvalidArgumentException('No verification keys provided');
        }
        $literalData = LiteralData::fromText($this->getText());
        $verifications = [];
        foreach ($this->signature->getSignaturePackets() as $packet) {
            foreach ($verificationKeys as $key) {
                try {
                    $keyPacket = $key->toPublic()->getSigningKeyPacket(
                        $packet->getIssuerKeyID()->getKeyID()
                    );
                    $verifications[] = new Verification(
                        $keyPacket->getKeyID(),
                        new Signature([$packet]),
                        $packet->verify(
                            $keyPacket,
                            $literalData->getSignBytes(),
                            $time
                        )
                    );
                }
                catch (\Throwable $e) {
                    Helper::getLooger()->error($e->getMessage());
                }
            }
        }
        return new self($this->getText(), $this->signature, $verifications);
    }
}
