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

use OpenPGP\Enum\{
    HashAlgorithm,
    KeyAlgorithm,
    PacketTag,
    SignatureType,
};

/**
 * OnePassSignature represents a One-Pass Signature packet.
 * See RFC 4880, section 5.4.
 * 
 * The One-Pass Signature packet precedes the signed data and contains enough information
 * to allow the receiver to begin calculating any hashes needed to verify the signature.
 * It allows the Signature packet to be placed at the end of the message,
 * so that the signer can compute the entire signed message in one pass.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
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
        private readonly int $nested
    )
    {
        parent::__construct(PacketTag::OnePassSignature);
    }

    /**
     * Reads one pass signature packet from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        $version = ord($bytes[$offset++]);
        if ($version != self::VERSION) {
            throw new \RuntimeException(
                "Version $version of the one-pass signature packet is unsupported.",
            );
        }

        $signatureType = SignatureType::from(ord($bytes[$offset++]));
        $hashAlgorithm = HashAlgorithm::from(ord($bytes[$offset++]));
        $keyAlgorithm = KeyAlgorithm::from(ord($bytes[$offset++]));
        $issuerKeyID = substr($bytes, $offset, 8);
        return new self(
            $signatureType,
            $hashAlgorithm,
            $keyAlgorithm,
            $issuerKeyID,
            ord($bytes[$offset + 8])
        );
    }

    /**
     * Gets signature type
     *
     * @return SignatureType
     */
    public function getSignatureType(): SignatureType
    {
        return $this->signatureType;
    }

    /**
     * Gets hash algorithm
     *
     * @return HashAlgorithm
     */
    public function getHashAlgorithmt(): HashAlgorithm
    {
        return $this->hashAlgorithm;
    }

    /**
     * Gets key algorithm
     *
     * @return KeyAlgorithm
     */
    public function getKeyAlgorithm(): KeyAlgorithm
    {
        return $this->keyAlgorithm;
    }

    /**
     * Gets issuer key ID
     *
     * @return string
     */
    public function getIssuerKeyID(): string
    {
        return $this->issuerKeyID;
    }

    /**
     * Gets nested
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
