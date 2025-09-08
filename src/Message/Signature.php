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
use OpenPGP\Packet\{LiteralData, PacketList};
use OpenPGP\Type\{
    CleartextMessageInterface,
    KeyInterface,
    KeyPacketInterface,
    LiteralDataInterface,
    PacketListInterface,
    SignatureInterface,
    SignaturePacketInterface,
};

/**
 * Signature class
 *
 * Class that represents a detacted OpenPGP signature.
 *
 * @package  OpenPGP
 * @category Message
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class Signature implements SignatureInterface
{
    private readonly PacketListInterface $packetList;

    private array $verificationErrors = [];

    /**
     * Constructor
     *
     * @param PacketListInterface $packetList
     * @return self
     */
    public function __construct(PacketListInterface $packetList)
    {
        $this->packetList = $packetList->whereType(
            SignaturePacketInterface::class,
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
        return self::fromBytes(
            Armor::decode($armored)->assert(ArmorType::Signature)->getData(),
        );
    }

    /**
     * Read signature from binary string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        return new self(PacketList::decode($bytes));
    }

    /**
     * {@inheritdoc}
     */
    public function getSigningKeyIDs(bool $toHex = false): array
    {
        return array_map(
            static fn($packet) => $packet->getIssuerKeyID($toHex),
            $this->getPackets(),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getVerificationErrors(): array
    {
        return $this->verificationErrors;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        array $verificationKeys,
        LiteralDataInterface $literalData,
        ?DateTimeInterface $time = null,
    ): array {
        $verificationKeys = array_filter(
            $verificationKeys,
            static fn($key) => $key instanceof KeyInterface,
        );
        if (empty($verificationKeys)) {
            throw new \InvalidArgumentException(
                "No verification keys provided.",
            );
        }
        $verifications = [];
        foreach ($this->packetList as $packet) {
            foreach ($verificationKeys as $key) {
                $keyPacket = null;
                try {
                    $keyPacket = $key
                        ->toPublic()
                        ->getSigningKeyPacket($packet->getIssuerKeyID());
                } catch (\Throwable $e) {
                    $this->verificationErrors[] = $e;
                }
                if ($keyPacket instanceof KeyPacketInterface) {
                    $isVerified = false;
                    $verificationError = "";
                    try {
                        $isVerified = $packet->verify(
                            $keyPacket,
                            $literalData->getSignBytes(),
                            $time,
                        );
                    } catch (\Throwable $e) {
                        $this->verificationErrors[] = $e;
                        $verificationError = $e->getMessage();
                    }

                    $verifications[] = new Verification(
                        $keyPacket->getKeyID(),
                        $packet,
                        $isVerified,
                        $verificationError,
                        array_map(
                            static fn($user) => $user->getUserID(),
                            array_filter(
                                $key->getUsers(),
                                static fn($user) => !empty($user->getUserID()),
                            ),
                        ),
                    );
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
        ?DateTimeInterface $time = null,
    ): array {
        return $this->verify(
            $verificationKeys,
            LiteralData::fromText($cleartext->getText()),
            $time,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        return Armor::encode(
            ArmorType::Signature,
            $this->getPacketList()->encode(),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getPacketList(): PacketListInterface
    {
        return $this->packetList;
    }

    /**
     * {@inheritdoc}
     */
    public function getPackets(): array
    {
        return $this->packetList->getPackets();
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return $this->armor();
    }
}
