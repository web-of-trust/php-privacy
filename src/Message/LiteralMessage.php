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

use OpenPGP\Enum\SymmetricAlgorithm;
use OpenPGP\Packet\Signature as SignaturePacket;
use OpenPGP\Packet\{
    CompressedData,
    OnePassSignature
};
use OpenPGP\Type\{
    EncryptedMessageInterface,
    LiteralDataPacketInterface,,
    LiteralMessageInterface,
    PacketInterface,
    SignatureInterface,
    SignaturePacketInterface,
    SignedMessageInterface,
};

/**
 * OpenPGP literal message class
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class LiteralMessage implements EncryptedMessageInterface, LiteralMessageInterface, SignedMessageInterface
{
    private readonly array $packets;

    private readonly LiteralDataPacketInterface $literalDataPacket;

    /**
     * Constructor
     *
     * @param array $packets
     * @return self
     */
    public function __construct(
        array $packets
    )
    {
        $this->packets = array_filter(
            $packets,
            static fn ($packet) => $packet instanceof PacketInterface
        );
        $this->literalDataPacket = array_pop(array_filter(
            $packets,
            static fn ($packet) => $packet instanceof LiteralDataPacketInterface
        ));
        if (empty($this->literalDataPacket)) {
            throw new \UnexpectedValueException('No literal data in packet list.');
        }
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
    public function getLiteralDataPacket(): LiteralDataPacketInterface
    {
        return $this->literalDataPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignature(): SignatureInterface
    {
        return new Signature(array_filter(
            $this->packets,
            static fn ($packet) => $packet instanceof SignaturePacketInterface
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function sign(
        array $signingKeys, ?DateTime $time = null
    ): SignedMessageInterface
    {
        $signaturePackets = [
            ...array_filter(
                $this->packets,
                static fn ($packet) => $packet instanceof SignaturePacketInterface
            ),
            ...$this->signDetached()->getSignaturePackets(),
        ];
        $onePassSignaturePackets = array_map(
            static fn ($packet) => OnePassSignature(
                $packet->getSignatureType(),
                $packet->getHashAlgorithm(),
                $packet->getKeyAlgorithm(),
                $packet->getIssuerKeyID()0
            ),
            $signaturePackets
        );

        return self([
            ...$onePassSignaturePackets,
            $this->literalDataPacket,
            ...$signaturePackets,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function signDetached(
        array $signingKeys, ?DateTime $time = null
    ): SignatureInterface
    {
        $signingKeys = array_filter(
            $signingKeys, static fn ($key) => $key instanceof PrivateKey
        );
        if (empty($signingKeys)) {
            throw new \InvalidArgumentException('No signing keys provided');
        }
        $packets = array_map(
            fn ($key) => SignaturePacket::createLiteralData(
                $key->getSigningKeyPacket(),
                $this->literalDataPacket,
                $time
            ),
            $signingKeys
        );
        return new Signature($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        array $encryptionKeys,
        array $passwords = [],
        SymmetricAlgorithm $sessionKeySymmetric = SymmetricAlgorithm::Aes128,
        SymmetricAlgorithm $encryptionKeySymmetric = SymmetricAlgorithm::Aes128
    ): EncryptedMessageInterface
    {
    }

    private static function unwrapCompressed(array $packets): array
    {
        $compressedPackets = array_filter(
            $packets,
            static fn ($packet) => $packet instanceof CompressedData
        );
        return array_pop($compressedPackets)?->getPacketList()->toArray() ?? $packets;
    }
}
