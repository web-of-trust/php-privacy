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

use OpenPGP\Enum\{SignatureSubpacketType, SupportFeature};
use OpenPGP\Packet\SignatureSubpacket;

/**
 * Features sub-packet class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class Features extends SignatureSubpacket
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
            SignatureSubpacketType::Features->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * From features
     *
     * @param int $features
     * @param bool $critical
     * @return Features
     */
    public static function fromFeatures(
        int $features = 0, bool $critical = false
    ): Features
    {
        return Features(chr($features), $critical);
    }

    /**
     * Supprts modification detection
     *
     * @return bool
     */
    public bool supprtModificationDetection()
    {
        return ord($this->data[0]) & SupportFeature::ModificationDetection->value
            == SupportFeature::ModificationDetection->value;
    }

    /**
     * Supprts aead encrypted data
     *
     * @return bool
     */
    public bool supportAeadEncryptedData()
    {
        return ord($this->data[0]) & SupportFeature::AeadEncryptedData->value
            == SupportFeature::AeadEncryptedData->value;
    }

    /**
     * Supprts version 5 public key
     *
     * @return bool
     */
    public bool supportVersion5PublicKey()
    {
        return ord($this->data[0]) & SupportFeature::Version5PublicKey->value
            == SupportFeature::Version5PublicKey->value;
    }
}
