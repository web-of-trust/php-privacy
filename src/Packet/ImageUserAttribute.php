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
 * Image user attribute subpacket class
 *
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ImageUserAttribute extends UserAttributeSubpacket
{
    const JPEG = 1;

    /**
     * Constructor
     *
     * @param string $data
     * @param bool $isLong
     * @return self
     */
    public function __construct(string $data = '', bool $isLong = false)
    {
        parent::__construct(self::JPEG, $data, $isLong);
    }

    public static function fromImageData(string $imageData): ImageUserAttribute
    {
        return ImageUserAttribute(implode([
            "\x10\x00\x01",
            chr(self::JPEG),
            str_repeat(chr(0), 12),
            $imageData,
        ]));
    }

    /**
     * Gets header length
     *
     * @return self
     */
    public function getHeaderLength(): int
    {
        $data = $this->getData();
        return (ord($data[1]) << 8) | ord($data[0]);
    }

    /**
     * Gets version
     *
     * @return self
     */
    public function getVersion(): int
    {
        $data = $this->getData();
        return ord($data[2]);
    }

    /**
     * Gets encoding
     *
     * @return self
     */
    public function getEncoding(): int
    {
        $data = $this->getData();
        return ord($data[3]);
    }

    public function getImageData(): string
    {
        $length = $this->getHeaderLength();
        return substr($this->getData(), $length);
    }
}
