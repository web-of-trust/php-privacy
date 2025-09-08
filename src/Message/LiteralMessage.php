<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Message;

use DateTimeInterface;
use OpenPGP\Common\{Armor, Config};
use OpenPGP\Enum\{
    AeadAlgorithm,
    ArmorType,
    CompressionAlgorithm,
    LiteralFormat,
    SymmetricAlgorithm,
};
use OpenPGP\Packet\Signature as SignaturePacket;
use OpenPGP\Packet\{
    CompressedData,
    OnePassSignature,
    LiteralData,
    PacketList,
    Padding,
    PublicKeyEncryptedSessionKey,
    SymEncryptedIntegrityProtectedData,
    SymmetricKeyEncryptedSessionKey,
};
use OpenPGP\Packet\Key\SessionKey;
use OpenPGP\Type\{
    EncryptedMessageInterface,
    KeyInterface,
    LiteralDataInterface,
    LiteralMessageInterface,
    NotationDataInterface,
    PacketListInterface,
    PrivateKeyInterface,
    SessionKeyInterface,
    SignatureInterface,
    SignaturePacketInterface,
    SignedMessageInterface,
};

/**
 * OpenPGP literal message class
 *
 * @package  OpenPGP
 * @category Message
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class LiteralMessage extends AbstractMessage implements
    LiteralMessageInterface,
    SignedMessageInterface
{
    /**
     * Read message from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        return self::fromBytes(
            Armor::decode($armored)->assert(ArmorType::Message)->getData(),
        );
    }

    /**
     * Read message from binary string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        return new self(PacketList::decode($bytes));
    }

    /**
     * Create new literal message object from literal data.
     *
     * @param string $literalData
     * @param string $filename
     * @param DateTimeInterface $time
     * @return self
     */
    public static function fromLiteralData(
        string $literalData,
        string $filename = "",
        ?DateTimeInterface $time = null,
    ): self {
        return new self(
            new PacketList([
                new LiteralData(
                    $literalData,
                    LiteralFormat::Binary,
                    $filename,
                    $time,
                ),
            ]),
        );
    }

    /**
     * Generate a new session key object.
     * Taking the algorithm preferences of the passed encryption keys, if any.
     *
     * @param array $encryptionKeys
     * @param defaultSymmetric $defaultSymmetric
     * @return SessionKeyInterface
     */
    public static function generateSessionKey(
        array $encryptionKeys,
        SymmetricAlgorithm $defaultSymmetric = SymmetricAlgorithm::Aes256,
    ): SessionKeyInterface {
        $preferredSymmetrics = [];
        foreach ($encryptionKeys as $key) {
            if (empty($preferredSymmetrics)) {
                $preferredSymmetrics = $key->getPreferredSymmetrics();
            } else {
                $preferredSymmetrics = array_filter(
                    $preferredSymmetrics,
                    static fn($symmetric) => in_array(
                        $symmetric,
                        $key->getPreferredSymmetrics(),
                        true,
                    ),
                );
            }
        }
        $symmetric = empty($preferredSymmetrics)
            ? $defaultSymmetric
            : reset($preferredSymmetrics);

        $preferredAeads = [
            AeadAlgorithm::Ocb,
            AeadAlgorithm::Gcm,
            AeadAlgorithm::Eax,
        ];
        $aeadProtect = Config::aeadProtect();
        foreach ($encryptionKeys as $key) {
            if ($key->aeadSupported()) {
                $preferredAeads = array_filter(
                    $preferredAeads,
                    static fn($aead) => in_array(
                        $aead,
                        $key->getPreferredAeads($symmetric),
                        true,
                    ),
                );
                $aeadProtect = true;
            } else {
                $aeadProtect = false;
                break;
            }
        }
        $aead = empty($preferredAeads)
            ? Config::getPreferredAead()
            : reset($preferredAeads);

        return SessionKey::produceKey($symmetric, $aeadProtect ? $aead : null);
    }

    /**
     * Encrypt a session key either with public keys, passwords, or both at once.
     *
     * @param SessionKeyInterface $sessionKey
     * @param array $encryptionKeys
     * @param array $passwords
     * @return PacketListInterface
     */
    public static function encryptSessionKey(
        SessionKeyInterface $sessionKey,
        array $encryptionKeys = [],
        array $passwords = [],
    ): PacketListInterface {
        if (empty($encryptionKeys) && empty($passwords)) {
            throw new \InvalidArgumentException(
                "No encryption keys or passwords provided.",
            );
        }
        return new PacketList([
            ...array_map(
                static fn(
                    $key,
                ) => PublicKeyEncryptedSessionKey::encryptSessionKey(
                    $key->toPublic()->getEncryptionKeyPacket(),
                    $sessionKey,
                ),
                $encryptionKeys,
            ), // pkesk packets
            ...array_map(
                static fn(
                    $password,
                ) => SymmetricKeyEncryptedSessionKey::encryptSessionKey(
                    $password,
                    $sessionKey,
                    $sessionKey->getSymmetric(),
                    $sessionKey->getAead(),
                ),
                $passwords,
            ), // skesk packets
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getLiteralData(): LiteralDataInterface
    {
        $packets = array_filter(
            self::unwrapCompressed($this->getPackets()),
            static fn($packet) => $packet instanceof LiteralDataInterface,
        );
        if (empty($packets)) {
            throw new \RuntimeException("No literal data in packet list.");
        }
        return array_pop($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function getSignature(): SignatureInterface
    {
        return new Signature(
            new PacketList(
                array_filter(
                    self::unwrapCompressed($this->getPackets()),
                    static fn($packet) => $packet instanceof
                        SignaturePacketInterface,
                ),
            ),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function sign(
        array $signingKeys,
        array $recipients = [],
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): self {
        $signaturePackets = [
            ...array_filter(
                self::unwrapCompressed($this->getPackets()),
                static fn($packet) => $packet instanceof
                    SignaturePacketInterface,
            ),
            ...$this->signDetached(
                $signingKeys,
                $recipients,
                $notationData,
                $time,
            )->getPackets(),
        ];

        $opsPackets = array_reverse(
            array_map(
                static fn($index, $packet) => OnePassSignature::fromSignature(
                    $packet,
                    $index == 0 ? 1 : 0,
                ),
                array_keys($signaturePackets),
                $signaturePackets,
            ),
        );
        // innermost OPS refers to the first signature packet

        return new self(
            new PacketList([
                ...$opsPackets,
                $this->getLiteralData(),
                ...$signaturePackets,
            ]),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function signDetached(
        array $signingKeys,
        array $recipients = [],
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): SignatureInterface {
        $signingKeys = array_filter(
            $signingKeys,
            static fn($key) => $key instanceof PrivateKeyInterface,
        );
        if (empty($signingKeys)) {
            throw new \InvalidArgumentException("No signing keys provided.");
        }
        return new Signature(
            new PacketList(
                array_map(
                    fn($key) => SignaturePacket::createLiteralData(
                        $key->getSecretKeyPacket(),
                        $this->getLiteralData(),
                        $recipients,
                        $notationData,
                        $time,
                    ),
                    $signingKeys,
                ),
            ),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        array $verificationKeys,
        ?DateTimeInterface $time = null,
    ): array {
        return $this->getSignature()->verify(
            $verificationKeys,
            $this->getLiteralData(),
            $time,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verifyDetached(
        array $verificationKeys,
        SignatureInterface $signature,
        ?DateTimeInterface $time = null,
    ): array {
        return $signature->verify(
            $verificationKeys,
            $this->getLiteralData(),
            $time,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        array $encryptionKeys = [],
        array $passwords = [],
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
    ): EncryptedMessageInterface {
        $encryptionKeys = array_filter(
            $encryptionKeys,
            static fn($key) => $key instanceof KeyInterface,
        );
        $sessionKey = self::generateSessionKey($encryptionKeys, $symmetric);
        $addPadding = $sessionKey->getAead() instanceof AeadAlgorithm;
        foreach ($encryptionKeys as $key) {
            if ($key->getVersion() !== 6) {
                $addPadding = false;
                break;
            }
        }
        $packetList = $addPadding
            ? new PacketList([
                ...$this->getPackets(),
                Padding::createPadding(
                    random_int(Padding::PADDING_MIN, Padding::PADDING_MAX),
                ),
            ])
            : $this->getPacketList();

        return new EncryptedMessage(
            new PacketList([
                ...self::encryptSessionKey(
                    $sessionKey,
                    $encryptionKeys,
                    $passwords,
                )->getPackets(),
                SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
                    $sessionKey,
                    $packetList,
                    $sessionKey->getAead(),
                ), // seipd packet
            ]),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function compress(
        CompressionAlgorithm $algorithm = CompressionAlgorithm::Uncompressed,
    ): self {
        if ($algorithm !== CompressionAlgorithm::Uncompressed) {
            return new self(
                new PacketList([
                    CompressedData::fromPackets(
                        self::unwrapCompressed($this->getPackets()),
                        $algorithm,
                    ),
                ]),
            );
        }
        return $this;
    }

    /**
     * Unwrap compressed packet list.
     *
     * @param array $packets
     * @return array
     */
    private static function unwrapCompressed(array $packets): array
    {
        $compressedPackets = array_filter(
            $packets,
            static fn($packet) => $packet instanceof CompressedData,
        );
        return array_pop($compressedPackets)?->getPacketList()?->getPackets() ??
            $packets;
    }
}
