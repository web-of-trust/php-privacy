<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Signature;

use OpenPGP\Enum\SignatureSubpacketType;
use OpenPGP\Packet\SignatureSubpacket;
use OpenPGP\Type\NotationDataInterface;

/**
 * NotationData sub-packet class.
 *
 * Class provided a NotationData object according to RFC 9580, section 5.2.3.24.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class NotationData extends SignatureSubpacket implements NotationDataInterface
{
    const int FLAG_LENGTH = 4;
    const int NAME_LENGTH = 2;
    const int VALUE_LENGTH = 2;

    const string SALT_NOTATION = "salt@php-openpgp.org";

    /**
     * Constructor
     *
     * @param string $data
     * @param bool $critical
     * @return self
     */
    public function __construct(string $data, bool $critical = false)
    {
        parent::__construct(
            SignatureSubpacketType::NotationData->value,
            $data,
            $critical,
        );
    }

    /**
     * From notation
     *
     * @param string $notationName
     * @param string $notationValue
     * @param bool $humanReadable
     * @param bool $critical
     * @return self
     */
    public static function fromNotation(
        string $notationName,
        string $notationValue,
        bool $humanReadable = false,
        bool $critical = false,
    ): self {
        return new self(
            self::notationToBytes(
                $notationName,
                $notationValue,
                $humanReadable,
            ),
            $critical,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function isHumanReadable(): bool
    {
        return $this->getData()[0] === "\x80";
    }

    /**
     * {@inheritdoc}
     */
    public function getNotationName(): string
    {
        $data = $this->getData();
        $nameLength =
            ((ord($data[self::FLAG_LENGTH]) & 0xff) << 8) +
            (ord($data[self::FLAG_LENGTH + 1]) & 0xff);
        $nameOffset =
            self::FLAG_LENGTH + self::NAME_LENGTH + self::VALUE_LENGTH;
        return substr($data, $nameOffset, $nameLength);
    }

    /**
     * {@inheritdoc}
     */
    public function getNotationValue(): string
    {
        $data = $this->getData();
        $nameLength =
            ((ord($data[self::FLAG_LENGTH]) & 0xff) << 8) +
            (ord($this->getData()[self::FLAG_LENGTH + 1]) & 0xff);
        $valueLength =
            ((ord($data[self::FLAG_LENGTH + self::NAME_LENGTH]) & 0xff) << 8) +
            (ord($data[self::FLAG_LENGTH + self::NAME_LENGTH + 1]) & 0xff);
        $valueOffset =
            self::FLAG_LENGTH +
            self::NAME_LENGTH +
            self::VALUE_LENGTH +
            $nameLength;
        return substr($data, $valueOffset, $valueLength);
    }

    private static function notationToBytes(
        string $notationName,
        string $notationValue,
        bool $humanReadable = false,
    ): string {
        $notationName = mb_convert_encoding($notationName, "UTF-8");
        $nameLength = min(strlen($notationName), 0xffff);
        if ($nameLength !== strlen($notationName)) {
            throw new \InvalidArgumentException(
                "Notation name exceeds maximum length.",
            );
        }

        $valueLength = min(strlen($notationValue), 0xffff);
        if ($valueLength !== strlen($notationValue)) {
            throw new \InvalidArgumentException(
                "Notation value exceeds maximum length.",
            );
        }

        return implode([
            $humanReadable ? "\x80\x00\x00\x00" : "\x00\x00\x00\x00",
            pack("n", $nameLength),
            pack("n", $valueLength),
            substr($notationName, 0, $nameLength),
            substr($notationValue, 0, $valueLength),
        ]);
    }
}
