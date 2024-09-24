<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
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
use OpenPGP\Enum\{
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
    SymEncryptedSessionKey,
};
use OpenPGP\Packet\Key\SessionKey;
use OpenPGP\Type\{
    EncryptedMessageInterface,
    KeyInterface,
    LiteralDataInterface,
    LiteralMessageInterface,
    NotationDataInterface,
    PrivateKeyInterface,
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
class LiteralMessage extends AbstractMessage implements LiteralMessageInterface, SignedMessageInterface
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
            Armor::decode($armored)->assert(ArmorType::Message)->getData()
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
        return new self(
            PacketList::decode($bytes)
        );
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
        string $filename = '',
        ?DateTimeInterface $time = null,
    ): self
    {
        return new self(new PacketList([new LiteralData(
            $literalData, LiteralFormat::Binary, $filename, $time
        )]));
    }

    /**
     * {@inheritdoc}
     */
    public function getLiteralData(): LiteralDataInterface
    {
        $packets = array_filter(
            self::unwrapCompressed($this->getPackets()),
            static fn ($packet) => $packet instanceof LiteralDataInterface,
        );
        if (empty($packets)) {
            throw new \RuntimeException(
                'No literal data in packet list.'
            );
        }
        return array_pop($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function getSignature(): SignatureInterface
    {
        return new Signature(new PacketList(array_filter(
            self::unwrapCompressed($this->getPackets()),
            static fn ($packet) => $packet instanceof SignaturePacketInterface,
        )));
    }

    /**
     * {@inheritdoc}
     */
    public function sign(
        array $signingKeys,
        array $recipients = [],
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): self
    {
        $signaturePackets = [
            ...array_filter(
                self::unwrapCompressed($this->getPackets()),
                static fn ($packet) => $packet instanceof SignaturePacketInterface,
            ),
            ...$this->createSignature(
                $signingKeys, $recipients, $notationData, $time
            )->getPackets(),
        ];

        $index = 0;
        $opsPackets = array_reverse(array_map(
            static function ($signature) use (&$index) {
                return OnePassSignature::fromSignature(
                    $signature,
                    (($index++) === 0) ? 1 : 0
                );
            },
            $signaturePackets
        )); // innermost OPS refers to the first signature packet

        return new self(new PacketList([
            ...$opsPackets,
            $this->getLiteralData(),
            ...$signaturePackets,
        ]));
    }

    /**
     * {@inheritdoc}
     */
    public function signDetached(
        array $signingKeys,
        array $recipients = [],
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): SignatureInterface
    {
        return $this->createSignature(
            $signingKeys,
            $recipients,
            $notationData,
            $time,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        array $verificationKeys, ?DateTimeInterface $time = null
    ): array
    {
        return $this->getSignature()->verify(
            $verificationKeys,
            $this->getLiteralData(),
            $time
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verifyDetached(
        array $verificationKeys,
        SignatureInterface $signature,
        ?DateTimeInterface $time = null,
    ): array
    {
        return $signature->verify(
            $verificationKeys, $this->getLiteralData(), $time
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        array $encryptionKeys = [],
        array $passwords = [],
        ?SymmetricAlgorithm $symmetric = null,
    ): EncryptedMessageInterface
    {
        $encryptionKeys = array_filter(
            $encryptionKeys,
            static fn ($key) => $key instanceof KeyInterface
        );
        if (empty($encryptionKeys) && empty($passwords)) {
            throw new \InvalidArgumentException(
                'No encryption keys or passwords provided.'
            );
        }

        $addPadding = false;
        $aeadSupported = Config::AEAD_SUPPORTED;
        foreach ($encryptionKeys as $key) {
            if (!$key->aeadSupported()) {
                $aeadSupported = false;
            }
            if ($key->getVersion() === 6) {
                $addPadding = true;
            }
        }
        $aead = ($aeadSupported && Config::aeadProtect()) ?
            Config::getPreferredAead() : null;

        $sessionKey = SessionKey::produceKey(
            $symmetric ?? Config::getPreferredSymmetric()
        );
        $pkeskPackets = array_map(
            static fn ($key) => PublicKeyEncryptedSessionKey::encryptSessionKey(
                $key->toPublic()->getEncryptionKeyPacket(),
                $sessionKey,
            ),
            $encryptionKeys,
        );
        $skeskPackets = array_map(
            static fn ($password) => SymEncryptedSessionKey::encryptSessionKey(
                $password,
                $sessionKey,
                $symmetric ?? Config::getPreferredSymmetric(),
                $aead,
            ),
            $passwords,
        );
        $packetList = ($addPadding || !empty($aead)) ? new PacketList([
            ...$this->getPackets(),
            Padding::createPadding(random_int(
                Config::PADDING_MIN, Config::PADDING_MAX)
            ),
        ]) : $this->getPacketList();
        $encryptedPacket = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
            $sessionKey, $packetList, $aead,
        );

        return new EncryptedMessage(new PacketList([
            ...$pkeskPackets,
            ...$skeskPackets,
            $encryptedPacket,
        ]));
    }

    /**
     * {@inheritdoc}
     */
    public function compress(
        ?CompressionAlgorithm $algorithm = null
    ): self
    {
        $algorithm = $algorithm ?? Config::getPreferredCompression();
        if ($algorithm !== CompressionAlgorithm::Uncompressed) {
            return new self(new PacketList([
                CompressedData::fromPackets($this->getPackets(), $algorithm),
            ]));
        }
        return $this;
    }

    /**
     * Create literal signature.
     *
     * @param array $signingKeys
     * @param array $recipients
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return SignatureInterface
     */
    private function createSignature(
        array $signingKeys,
        array $recipients = [],
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): SignatureInterface
    {
        $signingKeys = array_filter(
            $signingKeys,
            static fn ($key) => $key instanceof PrivateKeyInterface,
        );
        if (empty($signingKeys)) {
            throw new \InvalidArgumentException(
                'No signing keys provided.'
            );
        }
        return new Signature(new PacketList(array_map(
            fn ($key) => SignaturePacket::createLiteralData(
                $key->getSecretKeyPacket(),
                $this->getLiteralData(),
                $recipients,
                $notationData,
                $time,
            ),
            $signingKeys,
        )));
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
            static fn ($packet) => $packet instanceof CompressedData,
        );
        return array_pop(
            $compressedPackets
        )?->getPacketList()->getPackets() ?? $packets;
    }
}
