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
    AeadEncryptedData,
    CompressedData,
    OnePassSignature,
    LiteralData,
    PacketList,
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
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::Message) {
            throw new \UnexpectedValueException(
                'Armored text not of message type.'
            );
        }
        return new self(
            PacketList::decode($armor->getData())
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
        ?DateTimeInterface $time = null
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
            static fn ($packet) => $packet instanceof LiteralDataInterface
        );
        if (empty($packets)) {
            throw new \UnexpectedValueException(
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
            static fn ($packet) => $packet instanceof SignaturePacketInterface
        )));
    }

    /**
     * {@inheritdoc}
     */
    public function sign(
        array $signingKeys,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    ): self
    {
        $signaturePackets = [
            ...array_filter(
                self::unwrapCompressed($this->getPackets()),
                static fn ($packet) => $packet instanceof SignaturePacketInterface
            ),
            ...$this->createSignature(
                $signingKeys, false, $notationData, $time
            )->getPackets(),
        ];

        $index = 0;
        $length = count($signaturePackets);
        $onePassSignaturePackets = array_map(
            static fn ($packet) => new OnePassSignature(
                $packet->getSignatureType(),
                $packet->getHashAlgorithm(),
                $packet->getKeyAlgorithm(),
                $packet->getIssuerKeyID(),
                ((++$index) === $length) ? 1 : 0
            ),
            $signaturePackets
        );

        return new self(new PacketList([
            ...$onePassSignaturePackets,
            $this->getLiteralData(),
            ...$signaturePackets,
        ]));
    }

    /**
     * {@inheritdoc}
     */
    public function signDetached(
        array $signingKeys,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    ): SignatureInterface
    {
        return $this->createSignature(
            $signingKeys,
            true,
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
            false,
            $time
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verifyDetached(
        array $verificationKeys,
        SignatureInterface $signature,
        ?DateTimeInterface $time = null
    ): array
    {
        return $signature->verify(
            $verificationKeys, $this->getLiteralData(), true, $time
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        array $encryptionKeys = [],
        array $passwords = [],
        ?SymmetricAlgorithm $symmetric = null
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

        $sessionKey = SessionKey::produceKey(
            $symmetric ?? Config::getPreferredSymmetric()
        );
        $pkeskPackets = array_map(
            static fn ($key) => PublicKeyEncryptedSessionKey::encryptSessionKey(
                $key->toPublic()->getEncryptionKeyPacket(),
                $sessionKey
            ),
            $encryptionKeys
        );
        $skeskPackets = array_map(
            static fn ($password) => SymEncryptedSessionKey::encryptSessionKey(
                $password,
                $sessionKey,
                $symmetric ?? Config::getPreferredSymmetric()
            ),
            $passwords
        );

        $aeadSupported = true;
        foreach ($encryptionKeys as $key) {
            if (!$key->aeadSupported()) {
                $aeadSupported = false;
            }
        }
        if ($aeadSupported && Config::aeadProtect()) {
            $encryptedPacket = AeadEncryptedData::encryptPacketsWithSessionKey(
                $sessionKey, $this->getPacketList()
            );
        }
        else {
            $encryptedPacket = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
                $sessionKey, $this->getPacketList()
            );
        }

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
                CompressedData::fromPackets($this->getPackets(), $algorithm)
            ]));
        }
        return $this;
    }

    /**
     * Create literal signature.
     *
     * @param array $signingKeys
     * @param bool $detached
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return SignatureInterface
     */
    private function createSignature(
        array $signingKeys,
        bool $detached = false,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    ): SignatureInterface
    {
        $signingKeys = array_filter(
            $signingKeys,
            static fn ($key) => $key instanceof PrivateKeyInterface
        );
        if (empty($signingKeys)) {
            throw new \InvalidArgumentException(
                'No signing keys provided.'
            );
        }
        return new Signature(new PacketList(array_map(
            fn ($key) => SignaturePacket::createLiteralData(
                $key->getSigningKeyPacket(),
                $this->getLiteralData(),
                $detached,
                $notationData,
                $time
            ),
            $signingKeys
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
            static fn ($packet) => $packet instanceof CompressedData
        );
        return array_pop(
            $compressedPackets
        )?->getPacketList()->getPackets() ?? $packets;
    }
}
