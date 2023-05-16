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

use OpenPGP\Enum\{HashAlgorithm, KeyAlgorithm, SignatureSubpacketType};
use OpenPGP\Packet\SignatureSubpacket;

/**
 * SignatureTarget sub-packet class
 * RFC 4880, Section 5.2.3.25.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SignatureTarget extends SignatureSubpacket
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
            SignatureSubpacketType::SignatureTarget->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * From revocation
     *
     * @param KeyAlgorithm $keyAlgorithm
     * @param HashAlgorithm $hashAlgorithm
     * @param string $hashData
     * @param bool $critical
     * @return self
     */
    public static function fromRevocation(
        KeyAlgorithm $keyAlgorithm,
        HashAlgorithm $hashAlgorithm,
        string $hashData,
        bool $critical = false
    ): self
    {
        return new self(
            $this->hashDataToBytes($keyAlgorithm, $hashAlgorithm, $hashData),
            $critical
        );
    }

    /**
     * Gets key algorithm
     *
     * @return KeyAlgorithm
     */
    public function getKeyAlgorithm(): KeyAlgorithm
    {
        return KeyAlgorithm::from(ord($this->getData()[0]));
    }

    /**
     * Gets hash algorithm
     *
     * @return HashAlgorithm
     */
    public function getHashAlgorithm(): HashAlgorithm
    {
        return HashAlgorithm::from(ord($this->getData()[1]));
    }

    /**
     * Gets hashData
     *
     * @return string
     */
    public function getHashData(): string
    {
        return substr($this->getData(), 2);
    }

    private function hashDataToBytes(
        KeyAlgorithm $keyAlgorithm,
        HashAlgorithm $hashAlgorithm,
        string $hashData
    )
    {
        return implode([
            chr($keyAlgorithm->value),
            chr($hashAlgorithm->value),
            $hashData,
        ]);
    }
}
