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

use OpenPGP\Enum\{
    KeyFlag,
    SignatureSubpacketType,
};
use OpenPGP\Packet\SignatureSubpacket;

/**
 * KeyFlags sub-packet class
 * Holding the key flag values.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class KeyFlags extends SignatureSubpacket
{
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
            SignatureSubpacketType::KeyFlags->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * From flags
     *
     * @param int $flags
     * @param bool $critical
     * @return self
     */
    public static function fromFlags(
        int $flags, bool $critical = false
    ): self
    {
        return new self(self::flagsToBytes($flags), $critical);
    }

    /**
     * Gets key flags
     *
     * @return int
     */
    public function getFlags(): int
    {
        $flags = 0;
        $data = $this->getData();
        for ($i = 0; $i != strlen($data); $i++) {
          $flags |= ord($data[$i]) << ($i * 8);
        }
        return $flags;
    }

    /**
     * Is certify keys
     *
     * @return bool
     */
    public function isCertifyKeys(): bool
    {
        return ($this->getFlags() & KeyFlag::CertifyKeys->value)
            == KeyFlag::CertifyKeys->value;
    }

    /**
     * Is sign data
     *
     * @return bool
     */
    public function isSignData(): bool
    {
        return ($this->getFlags() & KeyFlag::SignData->value)
            == KeyFlag::SignData->value;
    }

    /**
     * Is encrypt communication
     *
     * @return bool
     */
    public function isEncryptCommunication(): bool
    {
        return ($this->getFlags() & KeyFlag::EncryptCommunication->value)
            == KeyFlag::EncryptCommunication->value;
    }

    /**
     * Is Eencrypt storage
     *
     * @return bool
     */
    public function isEncryptStorage(): bool
    {
        return ($this->getFlags() & KeyFlag::EncryptStorage->value)
            == KeyFlag::EncryptStorage->value;
    }

    private static function flagsToBytes(int $flags): string
    {
        $size = 0;
        $bytes = [];
        for ($i = 0; $i < 4; $i++) {
            $bytes[$i] = chr(($flags >> ($i * 8)) & 0xff);
            if (ord($bytes[$i]) != 0) {
                $size = $i;
            }
        }
        return substr(implode($bytes), 0, $size + 1);
    }
}
