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

/**
 * Sub packet reader class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
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
        private readonly int $offset = 0,
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
     * Get offset
     * 
     * @return int
     */
    public function getOffset(): int
    {
        return $this->offset;
    }

    /**
     * Get is long
     * 
     * @return bool
     */
    public function isLong(): bool
    {
        return $this->isLong;
    }

    /**
     * Read sub packet from byte string
     *
     * @param string $bytes
     * @param int $offset
     * @return SubpacketReader
     */
    public static function read(
        string $bytes, int $offset = 0
    ): SubpacketReader
    {
        $header = ord($bytes[$offset++]);
        if ($header < 192) {
            return new SubpacketReader(
                ord($bytes[$offset]),
                substr($bytes, $offset + 1, $header - 1),
                $offset + $header
            );
        }
        elseif ($header < 255) {
            $length = (($header - 192) << 8) + (ord($bytes[$offset++])) + 192;
            return new SubpacketReader(
                ord($bytes[$offset]),
                substr($bytes, $offset + 1, $length - 1),
                $offset + $length,
            );
        }
        elseif ($header == 255) {
            $unpacked = unpack('N', substr($bytes, $offset, 4));
            $length = reset($unpacked);
            $offset += 4;
            return new SubpacketReader(
                $bytes[$offset],
                substr($bytes, $offset + 1, $length - 1),
                $offset + $length,
                true,
            );
        }
        return new SubpacketReader();
    }
}
