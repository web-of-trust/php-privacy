<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\{
    HashAlgorithm,
    KeyAlgorithm,
    PacketTag,
    SignatureType,
};

/**
 * Implementation an OpenPGP One-Pass Signature packet (Tag 4).
 * 
 * See RFC 9580, section 5.4.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class OnePassSignature extends AbstractPacket
{
    const VERSION_3 = 3;
    const VERSION_6 = 6;

    /**
     * Constructor
     *
     * @param int $version
     * @param SignatureType $signatureType
     * @param HashAlgorithm $hashAlgorithm
     * @param KeyAlgorithm $keyAlgorithm
     * @param string $salt
     * @param string $issuerFingerprint
     * @param string $issuerKeyID
     * @param int $isLast
     * @return self
     */
    public function __construct(
        private readonly int $version,
        private readonly SignatureType $signatureType,
        private readonly HashAlgorithm $hashAlgorithm,
        private readonly KeyAlgorithm $keyAlgorithm,
        private readonly string $salt,
        private readonly string $issuerFingerprint,
        private readonly string $issuerKeyID,
        private readonly int $isLast = 0,
    )
    {
        parent::__construct(PacketTag::OnePassSignature);
        if ($version != self::VERSION_3 && $version != self::VERSION_6) {
            throw new \RuntimeException(
                "Version $version of the one-pass signature packet is unsupported.",
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        // A one-octet version number.
        $version = ord($bytes[$offset++]);

        // A one-octet signature type.
        $signatureType = SignatureType::from(ord($bytes[$offset++]));

        // A one-octet number describing the hash algorithm used.
        $hashAlgorithm = HashAlgorithm::from(ord($bytes[$offset++]));

        // A one-octet number describing the public-key algorithm used.
        $keyAlgorithm = KeyAlgorithm::from(ord($bytes[$offset++]));

        $salt = '';
        $issuerFingerprint = '';
        if ($version === self::VERSION_6) {
            $saltLength = ord($bytes[$offset++]);
            $salt = substr($bytes, $offset, $saltLength);
            $offset += $saltLength;

            $issuerFingerprint = substr($bytes, $offset, 32);
            $offset += 32;
            $issuerKeyID = substr($issuerFingerprint, 0, 8);
        }
        else {
            // An eight-octet number holding the Key ID of the signing key.
            $issuerKeyID = substr($bytes, $offset, 8);
            $offset += 8;
        }

        /**
         * A one-octet number holding a flag showing whether the signature is nested.
         * A zero value indicates that the next packet is another One-Pass Signature packet
         * that describes another signature to be applied to the same message data.
         */
        $isLast = ord($bytes[$offset]);

        return new self(
            $version,
            $signatureType,
            $hashAlgorithm,
            $keyAlgorithm,
            $salt,
            $issuerFingerprint,
            $issuerKeyID,
            $isLast
        );
    }

    /**
     * Build one-pass signature packet from signature packet
     *
     * @param Signature $signature
     * @param int $isLast
     * @return self
     */
    public static function fromSignature(Signature $signature, int $isLast = 0): self
    {
        return new self(
            $signature->getVersion() === self::VERSION_6 ?
                    self::VERSION_6 : self::VERSION_3,
            $signature->getSignatureType(),
            $signature->getHashAlgorithm(),
            $signature->getKeyAlgorithm(),
            $signature->getSalt(),
            $signature->getIssuerFingerprint(),
            $signature->getIssuerKeyID(),
            $isLast
        );
    }

    /**
     * Get version
     *
     * @return int
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * Get signature type
     *
     * @return SignatureType
     */
    public function getSignatureType(): SignatureType
    {
        return $this->signatureType;
    }

    /**
     * Get hash algorithm
     *
     * @return HashAlgorithm
     */
    public function getHashAlgorithmt(): HashAlgorithm
    {
        return $this->hashAlgorithm;
    }

    /**
     * Get key algorithm
     *
     * @return KeyAlgorithm
     */
    public function getKeyAlgorithm(): KeyAlgorithm
    {
        return $this->keyAlgorithm;
    }

    /**
     * Get salt
     *
     * @return string
     */
    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * Get issuer fingerprint
     *
     * @return string
     */
    public function getIssuerFingerprint(): string
    {
        return $this->issuerFingerprint;
    }

    /**
     * Get issuer key ID
     *
     * @return string
     */
    public function getIssuerKeyID(): string
    {
        return $this->issuerKeyID;
    }

    /**
     * Packet is last
     *
     * @return int
     */
    public function isLast(): int
    {
        return $this->isLast;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        $data = [
            chr($this->version),
            chr($this->signatureType->value),
            chr($this->hashAlgorithm->value),
            chr($this->keyAlgorithm->value),
        ];
        if ($this->version === self::VERSION_6) {
            $data[] = chr(strlen($this->salt));
            $data[] = $this->salt;
            $data[] = $this->issuerFingerprint;
        }
        else {
            $data[] = $this->issuerKeyID;
        }
        $data[] = chr($this->isLast);
        return implode($data);
    }
}
