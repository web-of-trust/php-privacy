<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\{HashAlgorithm, KeyAlgorithm, PacketTag, SignatureType};

/**
 * OnePassSignature represents a One-Pass Signature packet.
 * See RFC 4880, section 5.4.
 *
 * The One-Pass Signature packet precedes the signed data and contains enough information
 * to allow the receiver to begin calculating any hashes needed to verify the signature.
 * It allows the Signature packet to be placed at the end of the message,
 * so that the signer can compute the entire signed message in one pass.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class OnePassSignature extends AbstractPacket
{
    const VERSION = 3;

    /**
     * Constructor
     *
     * @param SignatureType $signatureType
     * @param HashAlgorithm $hashAlgorithm
     * @param KeyAlgorithm $keyAlgorithm
     * @param string $issuerKeyID
     * @param int $nested
     * @return self
     */
    public function __construct(
        private readonly SignatureType $signatureType,
        private readonly HashAlgorithm $hashAlgorithm,
        private readonly KeyAlgorithm $keyAlgorithm,
        private readonly string $issuerKeyID,
        private readonly int $nested = 0
    ) {
        parent::__construct(PacketTag::OnePassSignature);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        // A one-octet version number. The current version is 3.
        $version = ord($bytes[$offset++]);
        if ($version != self::VERSION) {
            throw new \RuntimeException(
                "Version $version of the one-pass signature packet is unsupported."
            );
        }

        // A one-octet signature type.
        $signatureType = SignatureType::from(ord($bytes[$offset++]));

        // A one-octet number describing the hash algorithm used.
        $hashAlgorithm = HashAlgorithm::from(ord($bytes[$offset++]));

        // A one-octet number describing the public-key algorithm used.
        $keyAlgorithm = KeyAlgorithm::from(ord($bytes[$offset++]));

        // An eight-octet number holding the Key ID of the signing key.
        $issuerKeyID = substr($bytes, $offset, 8);

        /**
         * A one-octet number holding a flag showing whether the signature is nested.
         * A zero value indicates that the next packet is another One-Pass Signature packet
         * that describes another signature to be applied to the same message data.
         */
        $nested = ord($bytes[$offset + 8]);

        return new self(
            $signatureType,
            $hashAlgorithm,
            $keyAlgorithm,
            $issuerKeyID,
            $nested
        );
    }

    /**
     * Build one-pass signature packet from signature packet
     *
     * @param Signature $signature
     * @param int $nested
     * @return self
     */
    public static function fromSignature(
        Signature $signature,
        int $nested = 0
    ): self {
        return new self(
            $signature->getSignatureType(),
            $signature->getHashAlgorithm(),
            $signature->getKeyAlgorithm(),
            $signature->getIssuerKeyID(),
            $nested
        );
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
     * Get issuer key ID
     *
     * @return string
     */
    public function getIssuerKeyID(): string
    {
        return $this->issuerKeyID;
    }

    /**
     * Get nested
     *
     * @return int
     */
    public function getNested(): int
    {
        return $this->nested;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            chr(self::VERSION),
            chr($this->signatureType->value),
            chr($this->hashAlgorithm->value),
            chr($this->keyAlgorithm->value),
            $this->issuerKeyID,
            chr($this->nested),
        ]);
    }
}
