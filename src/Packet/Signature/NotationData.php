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
 * Class provided a NotationData object according to RFC2440, Chapter 5.2.3.15.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class NotationData extends SignatureSubpacket implements NotationDataInterface
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
     * @return self
     */
    public static function fromNotation(
        bool $humanReadable,
        string $notationName,
        string $notationValue,
        bool $critical = false
    ): self
    {
        return new self(
            self::notationToBytes(
                $humanReadable, $notationName, $notationValue
            ),
            $critical
        );
    }

    /**
     * {@inheritdoc}
     */
    public function isHumanReadable(): bool
    {
        return ord($this->getData()[0]) == 0x80;
    }

    /**
     * {@inheritdoc}
     */
    public function getNotationName(): string
    {
        $data = $this->getData();
        $nameLength = (((ord($data[self::FLAG_LENGTH]) & 0xff) << 8) +
            (ord($data[self::FLAG_LENGTH + 1]) & 0xff));
        $nameOffset = self::FLAG_LENGTH + self::NAME_LENGTH + self::VALUE_LENGTH;
        return substr($data, $nameOffset, $nameLength);
    }

    /**
     * {@inheritdoc}
     */
    public function getNotationValue(): string
    {
        $data = $this->getData();
        $nameLength = (((ord($data[self::FLAG_LENGTH]) & 0xff) << 8) +
            (ord($this->getData()[self::FLAG_LENGTH + 1]) & 0xff));
        $valueLength = (((ord($data[self::FLAG_LENGTH + self::NAME_LENGTH]) & 0xff) << 8) +
            (ord($data[self::FLAG_LENGTH + self::NAME_LENGTH + 1]) & 0xff));
        $valueOffset =  self::FLAG_LENGTH +
            self::NAME_LENGTH +
            self::VALUE_LENGTH +
            $nameLength;
        return substr($data, $valueOffset, $valueLength);
    }

    private static function notationToBytes(
        bool $humanReadable,
        string $notationName,
        string $notationValue
    ): string
    {
        $nameLength = min(strlen($notationName), 0xffff);
        if ($nameLength != strlen($notationName)) {
            throw new \InvalidArgumentException(
                'Notation name exceeds maximum length.'
            );
        }

        $valueLength = min(strlen($notationValue), 0xffff);
        if ($valueLength != strlen($notationValue)) {
            throw new \InvalidArgumentException(
                'Notation value exceeds maximum length.'
            );
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
