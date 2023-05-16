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

use OpenPGP\Enum\{KeyAlgorithm, RevocationKeyTag, SignatureSubpacketType};
use OpenPGP\Packet\SignatureSubpacket;

/**
 * RevocationKey sub-packet class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class RevocationKey extends SignatureSubpacket
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
            SignatureSubpacketType::RevocationKey->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * From revocation
     *
     * @param RevocationKeyTag $signatureClass
     * @param KeyAlgorithm $keyAlgorithm
     * @param string $fingerprint
     * @param bool $critical
     * @return RevocationKey
     */
    public static function fromRevocation(
        RevocationKeyTag $signatureClass,
        KeyAlgorithm $keyAlgorithm,
        string $fingerprint,
        bool $critical = false
    ): RevocationKey
    {
        return new RevocationKey(
            $this->revocationToBytes($signatureClass, $keyAlgorithm, $fingerprint), $critical
        );
    }

    /**
     * Gets signature class
     *
     * @return RevocationKeyTag
     */
    public function getSignatureClass(): RevocationKeyTag
    {
        return RevocationKeyTag::from(ord($this->getData()[0]));
    }

    /**
     * Gets key algorithm
     *
     * @return KeyAlgorithm
     */
    public function getKeyAlgorithm(): KeyAlgorithm
    {
        return KeyAlgorithm::from(ord($this->getData()[1]));
    }

    /**
     * Gets fingerprint
     *
     * @return string
     */
    public function getFingerprint(): string
    {
        return substr($this->getData(), 2);
    }

    private function revocationToBytes(
        RevocationKeyTag $signatureClass,
        KeyAlgorithm $keyAlgorithm,
        string $fingerprint
    )
    {
        return implode([
            chr($signatureClass->value),
            chr($keyAlgorithm->value),
            $fingerprint,
        ])
    }
}
