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

use OpenPGP\Enum\{KeyAlgorithm, PacketTag};

/**
 * Public key packet class
 * 
 * PublicKey represents an OpenPGP public key packet.
 * See RFC 4880, section 5.5.2.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class PublicKey extends AbstractPacket implements KeyPacketInterface, ForSigningInterface
{
	const KEY_VERSION = 4;

    private readonly string $fingerprint;

    private readonly string $keyID;

    /**
     * Constructor
     *
     * @param int $creationTime
     * @param Key\KeyParametersInterface $keyParameters
     * @param KeyAlgorithm $keyAlgorithm
     * @return self
     */
    public function __construct(
        private readonly int $creationTime,
        private readonly Key\KeyParametersInterface $keyParameters,
        private readonly KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign
    )
    {
        parent::__construct(PacketTag::PublicKey);
        $this->fingerprint = sha1($this->getSignBytes(), true);
        $this->keyID = substr($this->fingerprint, 12, 8);
    }

    /**
     * Read public key packets from byte string
     *
     * @param string $bytes
     * @return KeyPacketInterface
     */
    public static function fromBytes(string $bytes): KeyPacketInterface
    {
        $offset = 0;

        // A one-octet version number (3 or 4 or 5).
        $version = ord($bytes[$offset++]);
        if ($version !== self::KEY_VERSION) {
            throw new \UnexpectedValueException(
                "Version $version of the key packet is unsupported.",
            );
        }

        // A four-octet number denoting the time that the key was created.
        $unpacked = unpack('N', substr($bytes, $offset, 4));
        $creationTime = reset($unpacked);
        $offset += 4;

        // A one-octet number denoting the public-key algorithm of this key.
        $keyAlgorithm = KeyAlgorithm::from(ord($bytes[$offset++]));

        // A series of values comprising the key material.
        // This is algorithm-specific and described in section XXXX.
        $keyParameters = self::readKeyParameters(
            substr($bytes, $offset), $keyAlgorithm
        );

        return new PublicKey($creationTime, $keyParameters, $keyAlgorithm);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            chr(self::KEY_VERSION),
            pack('N', $this->creationTime),
            chr($this->keyAlgorithm->value),
            $this->keyParameters->toBytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getVersion(): int
    {
        return self::KEY_VERSION;
    }

    /**
     * {@inheritdoc}
     */
    public function getCreationTime(): int
    {
        return $this->creationTime;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyAlgorithm(): KeyAlgorithm
    {
        return $this->keyAlgorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyParameters(): ?Key\KeyParametersInterface
    {
        return $this->keyParameters;
    }

    /**
     * {@inheritdoc}
     */
    public function getFingerprint(): string
    {
        return $this->fingerprint;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyID(): string
    {
        return $this->keyID;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignBytes(): string
    {
        $bytes = $this->toBytes();
        return implode([
            "\x99",
            pack('n', strlen($bytes)),
            $bytes,
        ]);
    }

    private static function readKeyParameters(
        string $bytes, KeyAlgorithm $keyAlgorithm
    ): Key\KeyParametersInterface
    {
        return match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign => Key\RSAPublicParameters::fromBytes($bytes),
            KeyAlgorithm::RsaEncrypt => Key\RSAPublicParameters::fromBytes($bytes),
            KeyAlgorithm::RsaSign => Key\RSAPublicParameters::fromBytes($bytes),
            KeyAlgorithm::ElGamal => Key\ElGamalPublicParameters::fromBytes($bytes),
            KeyAlgorithm::Dsa => Key\DSAPublicParameters::fromBytes($bytes),
            KeyAlgorithm::Ecdh => Key\ECDHPublicParameters::fromBytes($bytes),
            KeyAlgorithm::EcDsa => Key\ECDSAPublicParameters::fromBytes($bytes),
            KeyAlgorithm::EdDsa => Key\EdDSAPublicParameters::fromBytes($bytes),
            default => throw new \UnexpectedValueException(
                "Unsupported PGP public key algorithm encountered",
            ),
        };
    }
}
