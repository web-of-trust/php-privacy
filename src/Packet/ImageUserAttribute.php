<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

/**
 * Image user attribute subpacket class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
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

    /**
     * Read image user attribute from byte string
     *
     * @param string $imageData
     * @return self
     */
    public static function fromImageData(
        string $imageData
    ): self
    {
        return new self(implode([
            "\x10\x00\x01",
            chr(self::JPEG),
            str_repeat("\x00", 12),
            $imageData,
        ]));
    }

    /**
     * Get header length
     *
     * @return int
     */
    public function getHeaderLength(): int
    {
        $data = $this->getData();
        return (ord($data[1]) << 8) | ord($data[0]);
    }

    /**
     * Get version
     *
     * @return int
     */
    public function getVersion(): int
    {
        return ord($this->getData()[2]);
    }

    /**
     * Get encoding
     *
     * @return int
     */
    public function getEncoding(): int
    {
        return ord($this->getData()[3]);
    }

    /**
     * Get image data
     *
     * @return string
     */
    public function getImageData(): string
    {
        return substr($this->getData(), $this->getHeaderLength());
    }
}
