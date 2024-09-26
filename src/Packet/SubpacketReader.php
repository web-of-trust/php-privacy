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
        private readonly bool $isLong = false
    ) {
    }

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
     * Sub packet is long
     *
     * @return bool
     */
    public function isLong(): bool
    {
        return $this->isLong;
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
                    $reader->isLong()
                ),
                SignatureSubpacketType::SignatureExpirationTime
                    => new Signature\SignatureExpirationTime(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::ExportableCertification
                    => new Signature\ExportableCertification(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::TrustSignature
                    => new Signature\TrustSignature(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::RegularExpression
                    => new Signature\RegularExpression(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::Revocable => new Signature\Revocable(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::KeyExpirationTime
                    => new Signature\KeyExpirationTime(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::PreferredSymmetricAlgorithms
                    => new Signature\PreferredSymmetricAlgorithms(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::RevocationKey
                    => new Signature\RevocationKey(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::IssuerKeyID
                    => new Signature\IssuerKeyID(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::NotationData
                    => new Signature\NotationData(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::PreferredHashAlgorithms
                    => new Signature\PreferredHashAlgorithms(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::PreferredCompressionAlgorithms
                    => new Signature\PreferredCompressionAlgorithms(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::KeyServerPreferences
                    => new Signature\KeyServerPreferences(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::PreferredKeyServer
                    => new Signature\PreferredKeyServer(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::PrimaryUserID
                    => new Signature\PrimaryUserID(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::PolicyURI => new Signature\PolicyURI(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::KeyFlags => new Signature\KeyFlags(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::SignerUserID
                    => new Signature\SignerUserID(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::RevocationReason
                    => new Signature\RevocationReason(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::Features => new Signature\Features(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::SignatureTarget
                    => new Signature\SignatureTarget(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::EmbeddedSignature
                    => new Signature\EmbeddedSignature(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::IssuerFingerprint
                    => new Signature\IssuerFingerprint(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::PreferredAeadAlgorithms
                    => new Signature\PreferredAeadAlgorithms(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::IntendedRecipientFingerprint
                    => new Signature\IntendedRecipientFingerprint(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                SignatureSubpacketType::PreferredAeadCiphers
                    => new Signature\PreferredAeadCiphers(
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
                ),
                default => new SignatureSubpacket(
                    $type->value,
                    $reader->getData(),
                    $critical,
                    $reader->isLong()
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
                    $reader->isLong()
                ),
                default => new UserAttributeSubpacket(
                    $reader->getType(),
                    $reader->getData(),
                    $reader->isLong()
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
        $isLong = false;
        $header = ord($bytes[$offset++]);
        if ($header < 192) {
            $length = $header;
        } elseif ($header < 255) {
            $length = ($header - 192 << 8) + ord($bytes[$offset++]) + 192;
        } else {
            $isLong = true;
            $length = Helper::bytesToLong($bytes, $offset);
            $offset += 4;
        }

        return new self(
            ord($bytes[$offset]),
            substr($bytes, $offset + 1, $length - 1),
            $offset + $length,
            $isLong
        );
    }
}
