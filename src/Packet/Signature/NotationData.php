<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Signature;

use OpenPGP\Enum\SignatureSubpacketType;
use OpenPGP\Packet\SignatureSubpacket;

/**
 * NotationData sub-packet class.
 * Class provided a NotationData object according to RFC2440, Chapter 5.2.3.15.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class NotationData extends SignatureSubpacket
{
    const FLAG_LENGTH  = 4;
    const NAME_LENGTH  = 2;
    const VALUE_LENGTH = 2;

    /**
     * Constructor
     *
     * @param string $data
     * @param bool $critical
     * @param bool $isLong
     * @return self
     */
    public function __construct(
        string $data,
        bool $critical = false,
        bool $isLong = false
    )
    {
        parent::__construct(
            SignatureSubpacketType::NotationData->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * From notation
     *
     * @param bool $humanReadable
     * @param string $notationName
     * @param string $notationValue
     * @param bool $critical
     * @return NotationData
     */
    public static function fromNotation(
        bool $humanReadable,
        string $notationName,
        string $notationValue,
        bool $critical = false
    ): NotationData
    {
        return NotationData(
            $this->notationToBytes($humanReadable, $notationName, $notationValue), $critical
        );
    }

    /**
     * Is human readable
     *
     * @return bool
     */
    public function isHumanReadable(): bool
    {
        return ord($this->data[0]) == 0x80;
    }

    /**
     * Gets notation name
     *
     * @return string
     */
    public function getNotationName(): string
    {
        $nameLength = (((ord($this->data[self::FLAG_LENGTH]) & 0xff) << 8) +
            (ord($this->data[self::FLAG_LENGTH + 1]) & 0xff));
        $nameOffset = self::FLAG_LENGTH + self::NAME_LENGTH + self::VALUE_LENGTH;
        return substr($this->data, $nameOffset, $nameLength);
    }

    /**
     * Gets notation value
     *
     * @return string
     */
    public function getNotationValue(): string
    {
        $nameLength = (((ord($this->data[self::FLAG_LENGTH]) & 0xff) << 8) +
            (ord($this->data[self::FLAG_LENGTH + 1]) & 0xff));
        $valueLength = (((ord($this->data[self::FLAG_LENGTH + self::NAME_LENGTH]) & 0xff) << 8) +
            (ord($this->data[self::FLAG_LENGTH + self::NAME_LENGTH + 1]) & 0xff));
        $valueOffset =  self::FLAG_LENGTH +
            self::NAME_LENGTH +
            self::VALUE_LENGTH +
            $nameLength;
        return substr($this->data, $valueOffset, $valueLength);
    }

    private function notationToBytes(
        bool $humanReadable,
        string $notationName,
        string $notationValue
    ): string
    {
        $nameLength = min(strlen($notationName), 0xffff);
        if ($nameLength != strlen($notationName)) {
            throw new \InvalidArgumentException('notationName exceeds maximum length.');
        }

        $valueLength = min(strlen($notationValue), 0xffff);
        if ($valueLength != strlen($notationValue)) {
            throw new \InvalidArgumentException('notationValue exceeds maximum length.');
        }

        return implode([
            $humanReadable ? chr(0x80) : str_repeat(chr(0), 4),
            chr(($nameLength >> 8) & 0xff),
            chr(($nameLength >> 0) & 0xff),
            chr(($valueLength >> 8) & 0xff),
            chr(($valueLength >> 0) & 0xff),
            substr($notationName, 0, $nameLength),
            substr($notationValue, 0, $valueLength),
        ]);
    }
}
