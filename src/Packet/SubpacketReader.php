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
     * @param int $offset
     * @param bool $isLong
     * @return self
     */
    public function __construct(
        private readonly int $type = 0,
        private readonly string $data = '',
        private readonly int $length = 0,
        private readonly bool $isLong = false
    )
    {
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
            $data = $reader->getData();
            $critical = (($reader->getType() & 0x80) != 0);
            $type = SignatureSubpacketType::from($reader->getType() & 0x7f);
            switch ($type) {
                case SignatureSubpacketType::SignatureCreationTime:
                    $subpackets[] = new Signature\SignatureCreationTime(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::SignatureExpirationTime:
                    $subpackets[] = new Signature\SignatureExpirationTime(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::ExportableCertification:
                    $subpackets[] = new Signature\ExportableCertification(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::TrustSignature:
                    $subpackets[] = new Signature\TrustSignature(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::RegularExpression:
                    $subpackets[] = new Signature\RegularExpression(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::Revocable:
                    $subpackets[] = new Signature\Revocable(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::KeyExpirationTime:
                    $subpackets[] = new Signature\KeyExpirationTime(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::PreferredSymmetricAlgorithms:
                    $subpackets[] = new Signature\PreferredSymmetricAlgorithms(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::RevocationKey:
                    $subpackets[] = new Signature\RevocationKey(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::IssuerKeyID:
                    $subpackets[] = new Signature\IssuerKeyID(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::NotationData:
                    $subpackets[] = new Signature\NotationData(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::PreferredHashAlgorithms:
                    $subpackets[] = new Signature\PreferredHashAlgorithms(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::PreferredCompressionAlgorithms:
                    $subpackets[] = new Signature\PreferredCompressionAlgorithms(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::KeyServerPreferences:
                    $subpackets[] = new Signature\KeyServerPreferences(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::PreferredKeyServer:
                    $subpackets[] = new Signature\PreferredKeyServer(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::PrimaryUserID:
                    $subpackets[] = new Signature\PrimaryUserID(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::PolicyURI:
                    $subpackets[] = new Signature\PolicyURI(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::KeyFlags:
                    $subpackets[] = new Signature\KeyFlags(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::SignerUserID:
                    $subpackets[] = new Signature\SignerUserID(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::RevocationReason:
                    $subpackets[] = new Signature\RevocationReason(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::Features:
                    $subpackets[] = new Signature\Features(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::SignatureTarget:
                    $subpackets[] = new Signature\SignatureTarget(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::EmbeddedSignature:
                    $subpackets[] = new Signature\EmbeddedSignature(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::IssuerFingerprint:
                    $subpackets[] = new Signature\IssuerFingerprint(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::PreferredAeadAlgorithms:
                    $subpackets[] = new Signature\PreferredAeadAlgorithms(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::IntendedRecipientFingerprint:
                    $subpackets[] = new Signature\IntendedRecipientFingerprint(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                case SignatureSubpacketType::PreferredAeadCiphers:
                    $subpackets[] = new Signature\PreferredAeadCiphers(
                        $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
                default:
                    $subpackets[] = new SignatureSubpacket(
                        $type->value, $reader->getData(), $critical, $reader->isLong()
                    );
                    break;
            }
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
            switch ($reader->getType()) {
                case ImageUserAttribute::JPEG:
                    $attributes[] = new ImageUserAttribute(
                        $reader->getData(),
                        $reader->isLong()
                    );
                    break;
                default:
                    $attributes[] = new UserAttributeSubpacket(
                        $reader->getType(),
                        $reader->getData(),
                        $reader->isLong()
                    );
                    break;
            }
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
        }
        elseif ($header < 255) {
            $length = (($header - 192) << 8) + (ord($bytes[$offset++])) + 192;
        }
        else {
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
