<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\SignatureSubpacketType;
use phpseclib3\Common\Functions\Strings;

/**
 * Sub packet reader class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SubpacketReader
{
    /**
     * Constructor
     *
     * @param int $type
     * @param string $data
     * @param int $length
     * @param bool $isLong
     * @return self
     */
    public function __construct(
        private readonly int $type = 0,
        private readonly string $data = "",
        private readonly int $length = 0,
    ) {}

    /**
     * Get type
     *
     * @return int
     */
    public function getType(): int
    {
        return $this->type;
    }

    /**
     * Get data
     *
     * @return string
     */
    public function getData(): string
    {
        return $this->data;
    }

    /**
     * Get length
     *
     * @return int
     */
    public function getLength(): int
    {
        return $this->length;
    }

    /**
     * Read signature sub packet from byte string
     *
     * @param string $bytes
     * @return array<SignatureSubpacket>
     */
    public static function readSignatureSubpackets(string $bytes): array
    {
        $subpackets = [];
        while (strlen($bytes)) {
            $reader = self::read($bytes);
            Strings::shift($bytes, $reader->getLength());
            $critical = ($reader->getType() & 0x80) != 0;
            $type = SignatureSubpacketType::from($reader->getType() & 0x7f);
            $subpackets[] = match ($type) {
                SignatureSubpacketType::SignatureCreationTime
                    => new Signature\SignatureCreationTime(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::SignatureExpirationTime
                    => new Signature\SignatureExpirationTime(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::ExportableCertification
                    => new Signature\ExportableCertification(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::TrustSignature
                    => new Signature\TrustSignature(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::RegularExpression
                    => new Signature\RegularExpression(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::Revocable => new Signature\Revocable(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::KeyExpirationTime
                    => new Signature\KeyExpirationTime(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::PreferredSymmetricAlgorithms
                    => new Signature\PreferredSymmetricAlgorithms(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::RevocationKey
                    => new Signature\RevocationKey(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::IssuerKeyID
                    => new Signature\IssuerKeyID($reader->getData(), $critical),
                SignatureSubpacketType::NotationData
                    => new Signature\NotationData(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::PreferredHashAlgorithms
                    => new Signature\PreferredHashAlgorithms(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::PreferredCompressionAlgorithms
                    => new Signature\PreferredCompressionAlgorithms(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::KeyServerPreferences
                    => new Signature\KeyServerPreferences(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::PreferredKeyServer
                    => new Signature\PreferredKeyServer(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::PrimaryUserID
                    => new Signature\PrimaryUserID(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::PolicyURI => new Signature\PolicyURI(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::KeyFlags => new Signature\KeyFlags(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::SignerUserID
                    => new Signature\SignerUserID(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::RevocationReason
                    => new Signature\RevocationReason(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::Features => new Signature\Features(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::SignatureTarget
                    => new Signature\SignatureTarget(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::EmbeddedSignature
                    => new Signature\EmbeddedSignature(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::IssuerFingerprint
                    => new Signature\IssuerFingerprint(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::PreferredAeadAlgorithms
                    => new Signature\PreferredAeadAlgorithms(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::IntendedRecipientFingerprint
                    => new Signature\IntendedRecipientFingerprint(
                    $reader->getData(),
                    $critical,
                ),
                SignatureSubpacketType::PreferredAeadCiphers
                    => new Signature\PreferredAeadCiphers(
                    $reader->getData(),
                    $critical,
                ),
                default => new SignatureSubpacket(
                    $type->value,
                    $reader->getData(),
                    $critical,
                ),
            };
        }
        return $subpackets;
    }

    /**
     * Read user attribute sub packet from byte string
     *
     * @param string $bytes
     * @return array
     */
    public static function readUserAttributes(string $bytes): array
    {
        $attributes = [];
        while (strlen($bytes)) {
            $reader = self::read($bytes);
            Strings::shift($bytes, $reader->getLength());
            $attributes[] = match ($reader->getType()) {
                ImageUserAttribute::JPEG => new ImageUserAttribute(
                    $reader->getData(),
                ),
                default => new UserAttributeSubpacket(
                    $reader->getType(),
                    $reader->getData(),
                ),
            };
        }
        return $attributes;
    }

    /**
     * Read sub packet from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function read(string $bytes): self
    {
        $offset = 0;
        $header = ord($bytes[$offset++]);
        if ($header < 192) {
            $length = $header;
        } elseif ($header < 255) {
            $length = ($header - 192 << 8) + ord($bytes[$offset++]) + 192;
        } else {
            $length = Helper::bytesToLong($bytes, $offset);
            $offset += 4;
        }

        return new self(
            ord($bytes[$offset]),
            substr($bytes, $offset + 1, $length - 1),
            $offset + $length,
        );
    }
}
